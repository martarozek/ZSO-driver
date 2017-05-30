#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/irqreturn.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/wait.h>

#include <asm/atomic.h>
#include <asm/spinlock.h>
#include <asm/uaccess.h>

#include "monter.h"
#include "monter_ioctl.h"

#define MONTER_MAX_DEVS (256)
#define MONTER_NAME "monter"
#define MONTER_MAX_MEMORY_SIZE 65536
#define MONTER_CMD_SIZE sizeof(uint32_t)
#define BAR0 0
#define MONTER_CMD_CNT 1024
#define DMA_SIZE (MONTER_CMD_CNT * MONTER_CMD_SIZE)

typedef irqreturn_t (*irq_handler_t)(int irq, void *dev);

/* prototypes */
static int probe(struct pci_dev *pdev, const struct pci_device_id *id);
static void remove(struct pci_dev *pdev);

static int monter_open(struct inode *, struct file *);
static long monter_ioctl(struct file *, unsigned int, unsigned long);
static int monter_mmap(struct file *, struct vm_area_struct *);
static ssize_t monter_write(struct file *, const char __user *, size_t, loff_t *);
static int monter_fsync(struct file *, loff_t, loff_t, int datasync);
static int monter_release(struct inode *, struct file *);
/* end prototypes */

/* circular buffer */
struct circ_buf {
    uint32_t *buf;
    int size; /* in sizeof(uint32_t) */
    int start; /* index */
    int end; /* index */
};

static struct circ_buf *new_circ_buf(uint32_t *addr, int size)
{
    struct circ_buf *cbuf;

    cbuf = kmalloc(sizeof(*cbuf), GFP_KERNEL);
    if (!cbuf) {
        return ERR_PTR(-ENOMEM);
    }

    cbuf->buf = addr;
    cbuf->size = size;
    cbuf->start = 0;
    cbuf->end = 0;

    return cbuf;
}

static void destroy_circ_buf(struct circ_buf *cbuf)
{
    if (cbuf) {
        kfree(cbuf);
    }
    return;
}

static int circ_buf_space(struct circ_buf *cbuf) /* empty space */
{
    /* always one less to tell apart full and empty buffer */

    if (!cbuf) {
        return -EINVAL;
    }
    if (cbuf->start == cbuf->end) { /* all empty */
        return cbuf->size - 1;
    }
    else if (cbuf->start > cbuf->end) {
        return (cbuf->start - cbuf->end) - 1;
    }
    else { /* cbuf->start < cbuf->end */
        return cbuf->start + (cbuf->size - cbuf->end) - 1;
    }
}

static struct circ_buf *circ_buf_write(struct circ_buf *cbuf, uint32_t obj)
{
    if (!cbuf) {
        return 0;
    }
    if (circ_buf_space(cbuf) == 0) { /* no space */
            return 0;
    }

    cbuf->buf[cbuf->end] = obj;
    cbuf->end = (cbuf->end + 1) % cbuf->size;

    return cbuf;
}

static uint32_t circ_buf_read(struct circ_buf *cbuf)
{
    if (!cbuf) {
        return -EINVAL;
    }
    if (cbuf->start == cbuf->end) {
        return -1; /* nothing to read */
    }

    return cbuf->buf[cbuf->start];
}

static struct circ_buf *circ_buf_move_head(struct circ_buf *cbuf)
{
    if (!cbuf) {
        return 0; /* null pointer */
    }
    if (cbuf->start == cbuf->end) {
        return 0; /* empty buffer */
    }

    cbuf->start = (cbuf->start + 1) % cbuf->size;

    return cbuf;
}
/* end circular buffer */

/* for allocating minors */
static DEFINE_IDR(monter_minor_idr);

/* private struct for handling devices */
struct monter_data {
    dev_t numbers;
    struct device *device;
    struct device *pdev_dev;
    struct cdev cdev;
    void __iomem *iomap;
    struct circ_buf *cmd_buf;
    dma_addr_t dma_handle_cmd_buf;
    spinlock_t dev_lock;
    wait_queue_head_t write_queue;
    struct context *last_served;
    struct list_head cmd_completion_wait_list;

    dma_addr_t dma_handle_empty_page;
    void *cpu_addr_empty_page;
};

/* private struct for handling individual users of the device */
struct context {
    struct monter_data *device;
    atomic_t cmd_count;
    uint32_t addr_a;
    uint32_t addr_b;
    unsigned long data_block_size;
    uint32_t *data_block;
    dma_addr_t dma_handle_data_block;
    /* synchronizacja */
    spinlock_t user_lock;
    wait_queue_head_t fsync_queue;
    struct mutex mutex;
};

/* private struct for contexts waiting for their commands to complete */
struct context_list_elem {
    struct list_head list;
    struct context *user_data;
    unsigned long counter;
};

static const struct file_operations monter_fops = {
    .owner = THIS_MODULE,
    .open = monter_open,
    .release = monter_release,
    .unlocked_ioctl = monter_ioctl,
    .mmap = monter_mmap,
    .write = monter_write,
    .fsync = monter_fsync,
};

static dev_t first_dev;
static struct class *monter_class;

static const struct pci_device_id pci_ids[] = {
    { PCI_DEVICE(MONTER_VENDOR_ID, MONTER_DEVICE_ID) },
    { 0, },
};
static struct pci_driver monter_driver = {
    .name = MONTER_NAME,
    .id_table = pci_ids,
    .probe = probe,
    .remove = remove,
};

/* nie może blokować!!! */
static irqreturn_t irq_handler(int irq, void *dev_id)
{
    struct pci_dev *pdev = dev_id;
    struct monter_data *data = pci_get_drvdata(pdev);


    if (pdev->device != MONTER_DEVICE_ID) {
        return IRQ_NONE;
    }

    iowrite32(MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW,
              data->iomap + MONTER_INTR);
    return IRQ_HANDLED;
}

static int probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
    int ret;
    struct monter_data *data;
    dma_addr_t dma_handle;
    uint32_t *cpu_addr;

    data = kzalloc(sizeof(*data), GFP_KERNEL);
    if (!data) {
        printk(KERN_INFO "error in allocating memory for monter\n");
        ret = -ENOMEM;
        goto out;
    }
    pci_set_drvdata(pdev, (void *) data);
    data->pdev_dev = &pdev->dev;

    ret = idr_alloc(&monter_minor_idr, (void *) data, 0, MONTER_MAX_DEVS, GFP_KERNEL);
    if (ret < 0) {
        printk(KERN_INFO "error in allocating minor for monter\n");
        goto out_malloc_data;
    }
    data->numbers = MKDEV(MAJOR(first_dev), ret);

    cdev_init(&data->cdev, &monter_fops);
    data->cdev.owner = THIS_MODULE;
    ret = cdev_add(&data->cdev, data->numbers, 1);
    if (ret < 0) {
        printk(KERN_INFO "error in adding char device for monter\n");
        goto out_cdev;
    }

    data->device = device_create(monter_class, &pdev->dev, data->numbers, 0, "%s%d", MONTER_NAME, MINOR(data->numbers));
    if (IS_ERR(data->device)) {
        printk(KERN_INFO "error in creating device for monter\n");
        ret = PTR_ERR(data->device);
        goto out_cdev;
    }

    ret = pci_enable_device(pdev);
    if (ret < 0) {
        printk(KERN_INFO "error in enabling device for monter\n");
        goto out_device;
    }

    ret = pci_request_regions(pdev, MONTER_NAME);  /* TODO z dokumentacji PCI najpierw enable, potem request regions, sprawdzić */
    if (ret < 0) {
        printk(KERN_INFO "error in requesting regions for monter\n");
        goto out_enable;
    }

    data->iomap = pci_iomap(pdev, BAR0, 0);
    if (!data->iomap) {
        printk(KERN_INFO "error in iomap for monter\n");
        ret = -ENOMEM;
        goto out_regions;
    }

    pci_set_master(pdev);

    ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
    if (ret < 0) {
        printk(KERN_INFO "error in setting dma mask for monter\n");
        goto out_master;
    }

    ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
    if (ret < 0) {
        printk(KERN_INFO "error in setting consistent dma mask for monter\n");
        goto out_master;
    }

    cpu_addr = dma_alloc_coherent(&pdev->dev, DMA_SIZE, &dma_handle, GFP_KERNEL);
    if (!cpu_addr) {
        printk(KERN_INFO "error in dma allocation for monter\n");
        ret = -ENOMEM;
        goto out_master;
    }
    data->cmd_buf = new_circ_buf(cpu_addr, MONTER_CMD_CNT - 1);
    data->dma_handle_cmd_buf = dma_handle;

    data->cpu_addr_empty_page = dma_alloc_coherent(&pdev->dev, MONTER_PAGE_SIZE,
                                                   &data->dma_handle_empty_page,
                                                   GFP_KERNEL);
    if (!data->cpu_addr_empty_page) {
        printk(KERN_INFO "error in empty page allocation for monter\n");
        ret = -ENOMEM;
        goto out_dma;
    }

    ret = request_irq(pdev->irq, irq_handler, IRQF_SHARED, MONTER_NAME, pdev);   /* TODO upewnić się że nie ma wiszących przerwań */
    if (ret < 0) {                                                               /* TODO sprawdzić czy name nie musi być z minorem */
        printk(KERN_INFO "error in registering interrupt handler for monter\n");
        goto out_empty_page;
    }

    init_waitqueue_head(&data->write_queue);
    INIT_LIST_HEAD(&data->cmd_completion_wait_list);

    /* clear interrupts */
    iowrite32(MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW,
              data->iomap + MONTER_INTR);

    /* switch on interrupts */
    iowrite32(MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD, data->iomap + MONTER_INTR_ENABLE);

    /* loop the command block */
    cpu_addr[MONTER_CMD_CNT - 1] = MONTER_CMD_JUMP(dma_handle);

    /* pass command block addresses */
    iowrite32(dma_handle, data->iomap + MONTER_CMD_READ_PTR);
    iowrite32(dma_handle, data->iomap + MONTER_CMD_WRITE_PTR);

    /* switch on the device */
    iowrite32(MONTER_ENABLE_CALC | MONTER_ENABLE_FETCH_CMD, data->iomap + MONTER_ENABLE);

    printk(KERN_INFO "probe successful for monter\n");
    ret = 0;
    goto out;

out_empty_page:
    dma_free_coherent(&pdev->dev, MONTER_PAGE_SIZE, data->cpu_addr_empty_page,
                      data->dma_handle_empty_page);
out_dma:
    dma_free_coherent(&pdev->dev, DMA_SIZE, cpu_addr, dma_handle);
    destroy_circ_buf(data->cmd_buf);
out_master:
    pci_clear_master(pdev);
    pci_iounmap(pdev, data->iomap);
out_regions:
    pci_release_regions(pdev);
out_enable:
    pci_disable_device(pdev);
out_device:
    device_destroy(monter_class, data->numbers);
out_cdev:
    cdev_del(&data->cdev);
    idr_remove(&monter_minor_idr, MINOR(data->numbers));
out_malloc_data:
    kfree(data);
    pci_set_drvdata(pdev, NULL);
out:
    return ret;
}

/* TODO sprawdzić kolejność */
static void remove(struct pci_dev *pdev)
{
    struct monter_data *data;

    data = pci_get_drvdata(pdev);
    if (!data) {
        printk(KERN_INFO "can't retrieve monter's data\n");
        return;
    }

    /* czyszczenie bloku liczącego i kolejki poleceń */
    iowrite32(MONTER_RESET_CALC | MONTER_RESET_FIFO, data->iomap + MONTER_RESET);


    dma_free_coherent(&pdev->dev, DMA_SIZE, data->cmd_buf->buf, data->dma_handle_cmd_buf); /* TODO upewnić się że urządzenie nie korzysta z dma */
    pci_iounmap(pdev, data->iomap);
    device_destroy(monter_class, data->numbers);
    cdev_del(&data->cdev);
    idr_remove(&monter_minor_idr, MINOR(data->numbers));

    if (data->cmd_buf) {
        destroy_circ_buf(data->cmd_buf);
    }
    kfree(data);
    pci_set_drvdata(pdev, 0);

    free_irq(pdev->irq, (void *) pdev); /* TODO upewnić się że monter już nie zgłosi przerwań */
    pci_release_regions(pdev);
    pci_disable_device(pdev);

    return;
}

static int __init monter_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&first_dev, 0, MONTER_MAX_DEVS, MONTER_NAME);
    if (ret < 0) {
        printk(KERN_INFO "error in allocating chrdev region for monter\n");
        goto out;
    }

    monter_class = class_create(THIS_MODULE, MONTER_NAME);
    if (!monter_class) {
        printk(KERN_INFO "error in creating class for monter\n");
        ret = -ENOMEM;
        goto out_chrdev;
    }

    ret = pci_register_driver(&monter_driver);
    if (ret < 0) {
        printk(KERN_INFO "error in driver registration for monter\n");
        goto out_class;
    }

    ret = 0;
    goto out;


out_class:
    class_destroy(monter_class);
out_chrdev:
    unregister_chrdev_region(first_dev, MONTER_MAX_DEVS);
out:
    return ret;
}

static void __exit monter_cleanup(void)
{
    pci_unregister_driver(&monter_driver);
    unregister_chrdev_region(first_dev, MONTER_MAX_DEVS);
    class_destroy(monter_class);
    printk(KERN_INFO "papa\n");
    return;
}

static int validate_commands(uint32_t* commands, size_t count, struct context *user_data) {
    int i;
    uint32_t cmd, addr_a, addr_b, addr_d, size;

    if (!commands) {
        return -EINVAL;
    }


    for (i = 0; i < count; ++i) {
        cmd = commands[i];
        addr_a = user_data->addr_a;
        addr_b = user_data->addr_b;

        switch (MONTER_CMD_KIND(cmd)) {
            case MONTER_CMD_KIND_ADDR_AB:
                addr_a = MONTER_CMD_ADDR_A(cmd);
                if (addr_a >= user_data->data_block_size) {
                    return -EINVAL;
                }

                addr_b = MONTER_CMD_ADDR_B(cmd);
                if (addr_b >= user_data->data_block_size) {
                    return -EINVAL;
                }
                user_data->addr_a = addr_a;
                user_data->addr_b = addr_b;
                break;
            case MONTER_CMD_KIND_RUN:
                if (!addr_a || !addr_b) {
                    return -EINVAL;
                }

                if (cmd & (1 << 17)) {
                    return -EINVAL;
                }

                addr_d = MONTER_CMD_ADDR_D(cmd);
                size = MONTER_CMD_RUN_SIZE(cmd);

                switch (MONTER_CMD_SUBTYPE(cmd)) {
                    case MONTER_CMD_SUBTYPE_RUN_MULT:
                        if (addr_a + (size + 1) >= user_data->data_block_size) {
                            return -EINVAL;
                        }
                        if (addr_b + (size + 1) >= user_data->data_block_size) {
                            return -EINVAL;
                        }
                        if (addr_d + (size + 1)*2 >= user_data->data_block_size) {
                            return -EINVAL;
                        }
                        break;
                    case MONTER_CMD_SUBTYPE_RUN_REDC:
                        if (addr_d + (size + 1)*2 >= user_data->data_block_size) {
                            return -EINVAL;
                        }
                        if (addr_b + (size + 1) >= user_data->data_block_size) {
                            return -EINVAL;
                        }
                        break;
                }
                break;
        }
    }

    return 0;
}

/*=============== FILE OPERATIONS ===========================================*/

static int monter_open(struct inode *inode, struct file *filp)
{
    struct monter_data *dev_data; /* device information */
    struct context *user_data; /* user information */

    dev_data = container_of(inode->i_cdev, struct monter_data, cdev);

    user_data = kzalloc(sizeof(*user_data), GFP_KERNEL);
    if (!user_data) {
        return -ENOMEM;
    }
    user_data->device = dev_data;

    init_waitqueue_head(&user_data->fsync_queue);
    spin_lock_init(&user_data->user_lock);
    mutex_init(&user_data->mutex);
    atomic_set(&user_data->cmd_count, 0);

    filp->private_data = user_data;

    return 0;
}

static long monter_ioctl(struct file *filp, unsigned int request, unsigned long param)
{
    int ret;
    struct context *user_data;

    if (request != MONTER_IOCTL_SET_SIZE) {
        ret = -ENOTTY;
        goto out;
    }

    if (!param || param % MONTER_PAGE_SIZE || param > MONTER_MAX_MEMORY_SIZE) {
        ret = -EINVAL;
        goto out;
    }

    user_data = filp->private_data;

    mutex_lock(&user_data->mutex);
    if (user_data->data_block) { /* data block is already allocated */
        ret = -EINVAL;
        goto out_mutex;
    }

    user_data->data_block = dma_alloc_coherent(user_data->device->pdev_dev, param,
            &user_data->dma_handle_data_block, GFP_KERNEL);

    if (!user_data->data_block) {
        ret = -ENOMEM;
        goto out_mutex;
    }

    user_data->data_block_size = param;

    ret = 0;
    goto out_mutex;

out_mutex:
    mutex_unlock(&user_data->mutex);
out:
    return ret;
}

static int monter_mmap(struct file *filp, struct vm_area_struct *vma)
{
    int ret;
    struct context *con = filp->private_data;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long psize = con->data_block_size - offset;
    unsigned long vsize = vma->vm_end - vma->vm_start;
    unsigned long phys_addr = virt_to_phys(con->data_block);

    if (vma->vm_flags != VM_SHARED) {
        return -EINVAL;
    }

    if (vsize > psize) {
        return -EINVAL;
    }

    ret = remap_pfn_range(vma, vma->vm_start, (phys_addr + offset) >> PAGE_SHIFT,
                    con->data_block_size, vma->vm_page_prot);

    if (ret < 0) {
        return -EAGAIN;
    }

    return 0;
}

static ssize_t monter_write(struct file *filp, const char *buf, size_t count, loff_t *fpos)
{
    int ret, i;
    struct context *user_data = filp->private_data;
    struct monter_data *dev = user_data->device;
    uint32_t *commands;
    uint32_t addr_a, addr_b, addr_d, sizeM1, cmd;
    int space_needed = 2; /* at least one command plus counter */
    unsigned long flags;
    size_t to_read, read = 0;
    int page_cnt, unused_page_cnt, free_space, cmds_to_send, cmds_sent, cmd_pack;
    int counter_index;
    struct context_list_elem *entry;

    mutex_lock(&user_data->mutex);
    if (!user_data->data_block) { /* write before ioctl */
        ret = -EINVAL;
        mutex_unlock(&user_data->mutex);
        goto out;
    }
    mutex_unlock(&user_data->mutex);

    if (count % MONTER_CMD_SIZE) {
        ret = -EINVAL;
        goto out;
    }

    commands = kmalloc(MONTER_CMD_CNT*MONTER_CMD_SIZE, GFP_KERNEL);
    if (!commands) {
        ret = -ENOMEM;
        goto out;
    }

    addr_a = user_data->addr_a;
    addr_b = user_data->addr_b;
    while (read < count) {
        to_read = min(sizeof(commands)*sizeof(uint32_t), count-read);
        if (copy_from_user(commands, buf+read, to_read)) {
            ret = -EFAULT;
            goto out_malloc;
        }
        read += to_read;

        if (validate_commands(commands, count, user_data) < 0) {
            ret = -EINVAL;
            user_data->addr_a = addr_a;
            user_data->addr_b = addr_b;
            goto out_malloc;
        }
    }
    user_data->addr_a = addr_a;
    user_data->addr_b = addr_b;
    read = 0;

    /* commands validated */

    while (read < count) {
        to_read = min(MONTER_CMD_CNT*MONTER_CMD_SIZE, count - read);
        if (copy_from_user(commands, buf + read, to_read)) {
            ret = -EFAULT;
            goto out_malloc;
        }
        read += to_read;
        cmds_to_send = to_read / MONTER_CMD_SIZE;
        cmds_sent = 0;

        spin_lock_irqsave(&dev->dev_lock, flags);
        if (dev->last_served != user_data) {
            /* need to remap pages */
            space_needed = 2 + MONTER_PAGE_NUM;
        }

        while (cmds_to_send) {
            /* wait if buffer is full */
            if (circ_buf_space(dev->cmd_buf) < space_needed) {
                spin_unlock_irqrestore(&dev->dev_lock, flags);
                wait_event(dev->write_queue, circ_buf_space(dev->cmd_buf) >= space_needed);
                spin_lock_irqsave(&dev->dev_lock, flags);
            }

            /* check if someone hasn't come in the meantime */
            space_needed = 2;
            if (dev->last_served != user_data) {
                space_needed += MONTER_PAGE_NUM;
            }

            /* remap pages if someone else was using the device before */
            if (dev->last_served != user_data) {
                page_cnt = user_data->data_block_size / MONTER_PAGE_SIZE;
                for (i = 0; i < page_cnt; ++i) {
                    cmd = MONTER_CMD_PAGE(i, user_data->dma_handle_data_block + i*MONTER_PAGE_SIZE, 0);
                    circ_buf_write(dev->cmd_buf, cmd);
                }

                /* map empty space to a special empty page */
                unused_page_cnt = MONTER_PAGE_NUM - page_cnt;
                for (i = 0; i < unused_page_cnt; ++i) {
                    cmd = MONTER_CMD_PAGE(i, dev->dma_handle_empty_page + i*MONTER_PAGE_SIZE, 0);
                    circ_buf_write(dev->cmd_buf, cmd);
                }

                /* resend addresses */
                if (MONTER_CMD_KIND(commands[cmds_sent]) != MONTER_CMD_KIND_ADDR_AB) {
                    cmd = MONTER_CMD_ADDR_AB(user_data->addr_a, user_data->addr_b, 0);
                    circ_buf_write(dev->cmd_buf, cmd);
                }
            }
            dev->last_served = user_data;

            free_space = circ_buf_space(dev->cmd_buf);
            free_space--; /* one place for counter */
            cmd_pack = min(free_space, cmds_to_send);

            /* allocate memory for the context in a list */
            entry = kmalloc(sizeof(*entry), GFP_KERNEL);
            if (!entry) {
                ret = -ENOMEM;
                spin_unlock_irqrestore(&dev->dev_lock, flags);
                goto out_malloc;
            }

            /* read each command and send it to the device */
            for (i = 0; i < cmd_pack; ++i) {
                cmd = commands[cmds_sent + i];

                switch (MONTER_CMD_KIND(cmd)) {
                    case MONTER_CMD_KIND_ADDR_AB:
                        addr_a = MONTER_CMD_ADDR_A(cmd);
                        addr_b = MONTER_CMD_ADDR_B(cmd);
                        cmd = MONTER_CMD_ADDR_AB(addr_a, addr_b, 0);
                        break;

                    case MONTER_CMD_KIND_RUN:
                        addr_d = MONTER_CMD_ADDR_D(cmd);
                        sizeM1 = MONTER_CMD_RUN_SIZE(cmd);

                        switch (MONTER_CMD_SUBTYPE(cmd)) {
                            case MONTER_CMD_SUBTYPE_RUN_REDC:
                                cmd = MONTER_CMD_RUN_REDC(sizeM1, addr_d, 0);
                                break;

                            case MONTER_CMD_SUBTYPE_RUN_MULT:
                                cmd = MONTER_CMD_RUN_MULT(sizeM1, addr_d, 0);
                                break;
                        }
                        break;
                }
                circ_buf_write(dev->cmd_buf, cmd);
            }

            cmds_sent += cmd_pack;
            cmds_to_send -= cmd_pack;

            /* put a counter after the commands */
            counter_index = dev->cmd_buf->end;
            cmd = MONTER_CMD_COUNTER(counter_index, 1);
            circ_buf_write(dev->cmd_buf, cmd);

            /* put the context with its counter on a list */
            atomic_inc(&user_data->cmd_count);
            entry->user_data = user_data;
            entry->counter = counter_index;
            list_add_tail(&entry->list, &dev->cmd_completion_wait_list);
        }
        spin_unlock_irqrestore(&dev->dev_lock, flags);
    }

    ret = count;
    goto out_malloc;

out_malloc:
    kfree(commands);
out:
    return ret;
}

static int monter_fsync(struct file *filp, loff_t o1, loff_t o2, int ds)
{
    struct context *user_data = filp->private_data;

    wait_event(user_data->fsync_queue, atomic_read(&user_data->cmd_count) == 0);

    return 0;
}

static int monter_release(struct inode *n, struct file *filp)
{
    /* mmap */

    struct context *user_data = filp->private_data;

    if (!user_data) {
        return 0;
    }

    monter_fsync(filp, 0, 0, 0);

    if (user_data->data_block) {
        dma_free_coherent(user_data->device->pdev_dev, user_data->data_block_size,
                          user_data->data_block, user_data->dma_handle_data_block);
    }

    kfree(user_data);

    return 0;
}


module_init(monter_init);
module_exit(monter_cleanup);

MODULE_AUTHOR("Marta Rozek (mr360953@students.mimuw.edu.pl)");
MODULE_DESCRIPTION("PCI driver for Monter™ devices.");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, pci_ids);
