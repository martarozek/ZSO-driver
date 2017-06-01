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
#define MONTER_CMD_CNT 1024
#define DMA_SIZE (MONTER_CMD_CNT * MONTER_CMD_SIZE)
#define BAR0 0

typedef irqreturn_t (*irq_handler_t)(int irq, void *dev);

/*=============== PRIVATE STRUCTS ===========================================*/

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
    struct mutex mutex;
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

    int addr_set;
    unsigned long data_block_size;
    uint32_t *data_block;
    dma_addr_t dma_handle_data_block;

    spinlock_t user_lock;
    wait_queue_head_t fsync_queue;
    struct mutex mutex;

    atomic_t ref_count;
};

/* private struct for contexts waiting for their commands to complete */
struct context_list_elem {
    struct list_head list;
    struct context *user_data;
    unsigned long counter;
};

/*=============== PROTOTYPES ================================================*/

static int probe(struct pci_dev *pdev, const struct pci_device_id *id);
static void remove(struct pci_dev *pdev);

static int monter_open(struct inode *, struct file *);
static long monter_ioctl(struct file *, unsigned int, unsigned long);
static int monter_mmap(struct file *, struct vm_area_struct *);
static ssize_t monter_write(struct file *, const char __user *, size_t, loff_t *);
static int monter_fsync(struct file *, loff_t, loff_t, int datasync);
static int monter_release(struct inode *, struct file *);

static void monter_vma_open(struct vm_area_struct *);
static void monter_vma_close(struct vm_area_struct *);
static void context_ref_count_dec(struct context *);

/*=============== GLOBAL VARS ===============================================*/

/* for allocating minors */
static DEFINE_IDR(monter_minor_idr);

static const struct file_operations monter_fops = {
        .owner = THIS_MODULE,
        .open = monter_open,
        .release = monter_release,
        .unlocked_ioctl = monter_ioctl,
        .mmap = monter_mmap,
        .write = monter_write,
        .fsync = monter_fsync,
};

static struct vm_operations_struct monter_vm_ops = {
        .open = monter_vma_open,
        .close = monter_vma_close,
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

/*=============== CIRCULAR BUFFER ===========================================*/

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
    if (!circ_buf_space(cbuf)) { /* no space */
            return 0;
    }

    cbuf->buf[cbuf->end] = obj;
    cbuf->end = (cbuf->end + 1) % cbuf->size;

    return cbuf;
}

static struct circ_buf *circ_buf_move_read_ptr(struct circ_buf *cbuf, int pos)
{
    if (!cbuf) {
        return 0;
    }

    cbuf->start = pos % cbuf->size;

    return cbuf;
}

/*=============== INTERRUPT HANDLER =========================================*/

static irqreturn_t irq_handler(int irq, void *dev_id)
{
    struct pci_dev *pdev = dev_id;
    struct monter_data *data;
    int counter;
    struct list_head *pos, *q;
    struct context_list_elem *list_context;
    unsigned long flags;

    data = pci_get_drvdata(pdev);
    if (!data) {
        printk(KERN_INFO "can't retrieve monter's data\n");
        return IRQ_NONE;
    }

    if (!(ioread32(data->iomap + MONTER_INTR) &
            (MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW))) {
        return IRQ_NONE;
    }

    if (!ioread32(data->iomap + MONTER_INTR) & MONTER_INTR_NOTIFY) {
        goto out;
    }

    /* disable monter so that it doesn't change the counter registry */
    iowrite32((uint32_t) 0, data->iomap + MONTER_ENABLE);

    counter = ioread32(data->iomap + MONTER_COUNTER) & 0xffffff;

    spin_lock_irqsave(&data->dev_lock, flags);

    /* find all contexts waiting for this or earlier counter */
    /* decrease their command count and if 0 then wake and delete from the list */
    list_for_each_safe(pos, q , &data->cmd_completion_wait_list) {
        list_context = list_entry(pos, struct context_list_elem, list);

        if (atomic_dec_and_test(&list_context->user_data->cmd_count)) {
            wake_up_all(&list_context->user_data->fsync_queue);
        }
        list_del(pos);
        kfree(list_context);

        if (list_context->counter == counter) {
            break;
        }
    }

    /* move read pointer */
    circ_buf_move_read_ptr(data->cmd_buf, counter + 1);
    spin_unlock_irqrestore(&data->dev_lock, flags);

    /* there might be space in the command buffer */
    wake_up_all(&data->write_queue);

    goto out;

out:
    /* clear interrupts and enable the device back */
    iowrite32((uint32_t) (MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW),
              data->iomap + MONTER_INTR);
    iowrite32((uint32_t) (MONTER_ENABLE_CALC | MONTER_ENABLE_FETCH_CMD), data->iomap + MONTER_ENABLE);

    return IRQ_HANDLED;
}

/*=============== DEVICE OPERATIONS =========================================*/

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

    data->device = device_create(monter_class, &pdev->dev, data->numbers,
                                 0, "%s%d", MONTER_NAME, MINOR(data->numbers));
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

    ret = pci_request_regions(pdev, MONTER_NAME);
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

    mutex_init(&data->mutex);
    spin_lock_init(&data->dev_lock);
    init_waitqueue_head(&data->write_queue);
    INIT_LIST_HEAD(&data->cmd_completion_wait_list);
    /* loop the command block */
    cpu_addr[MONTER_CMD_CNT - 1] = MONTER_CMD_JUMP(dma_handle);


    iowrite32(MONTER_RESET_CALC | MONTER_RESET_FIFO, data->iomap + MONTER_RESET);

    /* clear interrupts */
    iowrite32(MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW,
              data->iomap + MONTER_INTR);

    /* pass command block addresses */
    iowrite32(dma_handle, data->iomap + MONTER_CMD_READ_PTR);
    iowrite32(dma_handle, data->iomap + MONTER_CMD_WRITE_PTR);

    /* switch on interrupts */
    iowrite32(MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW,
              data->iomap + MONTER_INTR_ENABLE);

    /* switch on the device */
    iowrite32(MONTER_ENABLE_CALC | MONTER_ENABLE_FETCH_CMD, data->iomap + MONTER_ENABLE);

    ret = request_irq(pdev->irq, irq_handler, IRQF_SHARED, MONTER_NAME, pdev);
    if (ret < 0) {
        printk(KERN_INFO "error in registering interrupt handler for monter\n");
        goto out_empty_page;
    }

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

static void remove(struct pci_dev *pdev)
{
    struct monter_data *data;

    data = pci_get_drvdata(pdev);
    if (!data) {
        printk(KERN_INFO "can't retrieve monter's data\n");
        return;
    }

    iowrite32(MONTER_INTR_NOTIFY | MONTER_INTR_INVALID_CMD | MONTER_INTR_FIFO_OVERFLOW,
              data->iomap + MONTER_INTR);
    iowrite32((uint32_t) 0, data->iomap + MONTER_INTR_ENABLE);
    iowrite32((uint32_t) 0, data->iomap + MONTER_ENABLE);
    iowrite32(MONTER_RESET_CALC | MONTER_RESET_FIFO, data->iomap + MONTER_RESET);

    dma_free_coherent(&pdev->dev, DMA_SIZE, data->cmd_buf->buf, data->dma_handle_cmd_buf);
    dma_free_coherent(&pdev->dev, MONTER_PAGE_SIZE, data->cpu_addr_empty_page,
                      data->dma_handle_empty_page);
    pci_clear_master(pdev);
    pci_iounmap(pdev, data->iomap);
    device_destroy(monter_class, data->numbers);
    cdev_del(&data->cdev);
    idr_remove(&monter_minor_idr, MINOR(data->numbers));

    if (data->cmd_buf) {
        destroy_circ_buf(data->cmd_buf);
    }
    kfree(data);
    pci_set_drvdata(pdev, 0);

    free_irq(pdev->irq, (void *) pdev);
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
    return;
}

static int validate_commands(uint32_t *commands, size_t count,
                             struct context *user_data,
                             uint32_t *addr_a, uint32_t *addr_b, int *addr_set)
{
    int i;
    uint32_t cmd, size, addr_d;

    if (!commands) {
        return -EINVAL;
    }

    for (i = 0; i < count; ++i) {
        cmd = commands[i];

        switch (MONTER_SWCMD_TYPE(cmd)) {
            case MONTER_SWCMD_TYPE_ADDR_AB:
                *addr_a = MONTER_SWCMD_ADDR_A(cmd);
                *addr_b = MONTER_SWCMD_ADDR_B(cmd);
                *addr_set = 1;

                if (*addr_a >= user_data->data_block_size) {
                    return -EINVAL;
                }

                if (*addr_b >= user_data->data_block_size) {
                    return -EINVAL;
                }
                break;

            case MONTER_SWCMD_TYPE_RUN_MULT:
                if (!*addr_set) {
                    return -EINVAL;
                }
                if (cmd & (1 << 17)) {
                    return -EINVAL;
                }

                addr_d = MONTER_SWCMD_ADDR_D(cmd);
                size = MONTER_SWCMD_RUN_SIZE(cmd);

                if (*addr_a + size*MONTER_CMD_SIZE - 1 > user_data->data_block_size) {
                    return -EINVAL;
                }
                if (*addr_b + size*MONTER_CMD_SIZE - 1 > user_data->data_block_size) {
                    return -EINVAL;
                }
                if (addr_d + size*MONTER_CMD_SIZE*2 - 1 > user_data->data_block_size) {
                    return -EINVAL;
                }
                break;

            case MONTER_SWCMD_TYPE_RUN_REDC:
                if (!*addr_set) {
                    return -EINVAL;
                }
                if (cmd & (1 << 17)) {
                    return -EINVAL;
                }

                addr_d = MONTER_SWCMD_ADDR_D(cmd);
                size = MONTER_SWCMD_RUN_SIZE(cmd);

                if (*addr_a + MONTER_CMD_SIZE - 1 > user_data->data_block_size) {
                    return -EINVAL;
                }
                if (*addr_b + size*MONTER_CMD_SIZE - 1 > user_data->data_block_size) {
                    return -EINVAL;
                }
                if (addr_d + size*MONTER_CMD_SIZE*2 - 1 > user_data->data_block_size) {
                    return -EINVAL;
                }
                break;

            default:
                return -EINVAL;
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
    atomic_set(&user_data->ref_count, 1);

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
    struct context *user_data = filp->private_data;
    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long psize = user_data->data_block_size - offset;
    unsigned long vsize = vma->vm_end - vma->vm_start;
    unsigned long phys_addr = (virt_to_phys(user_data->data_block) >> PAGE_SHIFT) + offset;

    mutex_lock(&user_data->mutex);
    if (!user_data->data_block) { /* mmap before ioctl */
        printk(KERN_INFO "error in monter: mmap before ioctl\n");
        ret = -EINVAL;
        mutex_unlock(&user_data->mutex);
        goto out;
    }
    mutex_unlock(&user_data->mutex);

    if (!(vma->vm_flags & VM_SHARED)) {
        printk(KERN_INFO "error in monter: wrong flags in mmap\n");
        ret = -EINVAL;
        goto out;
    }

    if (vsize > psize) {
        printk(KERN_INFO "error in monter: wrong size in mmap\n");
        ret = -EINVAL;
        goto out;
    }

    vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
    vma->vm_flags |= VM_IO;

    ret = remap_pfn_range(vma, vma->vm_start, phys_addr,
                          vsize, vma->vm_page_prot);

    if (ret < 0) {
        printk(KERN_INFO "error in monter: remap_pfn_range failed\n");
        ret = -EAGAIN;
        goto out;
    }

    vma->vm_ops = &monter_vm_ops;
    vma->vm_private_data = user_data;
    monter_vma_open(vma);

    ret = 0;
    goto out;

out:
    return ret;
}

static ssize_t monter_write(struct file *filp, const char *buf, size_t count, loff_t *fpos)
{
    int ret, i;
    struct context *user_data = filp->private_data;
    struct monter_data *dev = user_data->device;
    struct context_list_elem *entry;
    unsigned long flags;
    uint32_t *commands;
    uint32_t addr_a, addr_b, addr_d, sizeM1, cmd;
    size_t to_read, read;
    int page_cnt, free_space, cmds_to_send, cmds_sent, cmd_pack, counter_index, addr_set;
    int space_needed = 2; /* default minimum for one command + counter */

    mutex_lock(&user_data->mutex);
    if (!user_data->data_block) { /* write before ioctl */
        printk(KERN_INFO "error in monter: write before ioctl\n");
        ret = -EINVAL;
        mutex_unlock(&user_data->mutex);
        goto out;
    }
    mutex_unlock(&user_data->mutex);

    if (count % MONTER_CMD_SIZE) {
        printk(KERN_INFO "error in monter: unaligned write\n");
        ret = -EINVAL;
        goto out;
    }

    commands = kzalloc(MONTER_CMD_CNT*MONTER_CMD_SIZE, GFP_KERNEL);
    if (!commands) {
        printk(KERN_INFO "error in monter: memory allocation failed\n");
        ret = -ENOMEM;
        goto out;
    }

    mutex_lock(&user_data->mutex);

    addr_a = user_data->addr_a;
    addr_b = user_data->addr_b;
    addr_set = user_data->addr_set;

    read = 0;
    while (read < count) {
        to_read = min(MONTER_CMD_CNT*MONTER_CMD_SIZE, count-read);

        if (copy_from_user(commands, buf+read, to_read)) {
            printk(KERN_INFO "error in monter: copy_from_user failed\n");
            ret = -EFAULT;
            mutex_unlock(&user_data->mutex);
            goto out_malloc;
        }
        read += to_read;

        if (validate_commands(commands, to_read/MONTER_CMD_SIZE, user_data,
                              &addr_a, &addr_b, &addr_set) < 0) {
            printk(KERN_INFO "error in monter: command validation failed\n");
            ret = -EINVAL;
            mutex_unlock(&user_data->mutex);
            goto out_malloc;
        }
    }
    mutex_unlock(&user_data->mutex);
    read = 0;

    /* commands validated */
    while (read < count) {
        to_read = min(MONTER_CMD_CNT*MONTER_CMD_SIZE, count - read);

        if (copy_from_user(commands, buf + read, to_read)) {
            printk(KERN_INFO "error in monter: copy_from_user failed\n");
            ret = -EFAULT;
            goto out_malloc;
        }
        read += to_read;
        cmds_to_send = to_read / MONTER_CMD_SIZE;
        cmds_sent = 0;

        mutex_lock(&dev->mutex);
        if (dev->last_served != user_data) {
            /* need to remap pages */
            space_needed = 2 + MONTER_PAGE_NUM;
        }

        while (cmds_to_send) {
            /* wait if buffer is full */
            spin_lock_irqsave(&dev->dev_lock, flags);
            while (circ_buf_space(dev->cmd_buf) < space_needed) {
                spin_unlock_irqrestore(&dev->dev_lock, flags);
                wait_event(dev->write_queue, circ_buf_space(dev->cmd_buf) >= space_needed);
                spin_lock_irqsave(&dev->dev_lock, flags);
            }
            spin_unlock_irqrestore(&dev->dev_lock, flags);

            space_needed = 2;
            if (dev->last_served != user_data) {
                space_needed += MONTER_PAGE_NUM;
            }

            /* remap pages if someone else was using the device before */
            if (dev->last_served != user_data) {
                page_cnt = user_data->data_block_size / MONTER_PAGE_SIZE;
                for (i = 0; i < page_cnt; ++i) {
                    cmd = MONTER_CMD_PAGE(i, (uint32_t) user_data->dma_handle_data_block
                                             + i*MONTER_PAGE_SIZE, 0);

                    spin_lock_irqsave(&dev->dev_lock, flags);
                    circ_buf_write(dev->cmd_buf, cmd);
                    spin_unlock_irqrestore(&dev->dev_lock, flags);
                }

                /* map unused space to a special empty page */
                for (i = page_cnt; i < MONTER_PAGE_NUM; ++i) {
                    cmd = MONTER_CMD_PAGE(i, dev->dma_handle_empty_page, 0);

                    spin_lock_irqsave(&dev->dev_lock, flags);
                    circ_buf_write(dev->cmd_buf, cmd);
                    spin_unlock_irqrestore(&dev->dev_lock, flags);
                }

                /* resend addresses */
                if (MONTER_SWCMD_TYPE(commands[cmds_sent]) != MONTER_SWCMD_TYPE_ADDR_AB) {
                    cmd = MONTER_CMD_ADDR_AB(user_data->addr_a, user_data->addr_b, 0);

                    spin_lock_irqsave(&dev->dev_lock, flags);
                    circ_buf_write(dev->cmd_buf, cmd);
                    spin_unlock_irqrestore(&dev->dev_lock, flags);
                }
            }
            dev->last_served = user_data;

            spin_lock_irqsave(&dev->dev_lock, flags);
            free_space = circ_buf_space(dev->cmd_buf);
            spin_unlock_irqrestore(&dev->dev_lock, flags);

            free_space--; /* one place for counter */
            cmd_pack = min(free_space, cmds_to_send);

            /* allocate memory for the context in a list */
            entry = kmalloc(sizeof(*entry), GFP_KERNEL);
            if (!entry) {
                printk(KERN_INFO "error in monter: memory allocation failed\n");
                ret = -ENOMEM;
                mutex_unlock(&dev->mutex);
                goto out_malloc;
            }

            /* read each command and send it to the device */
            for (i = 0; i < cmd_pack; ++i) {
                cmd = commands[cmds_sent + i];

                switch (MONTER_SWCMD_TYPE(cmd)) {
                    case MONTER_SWCMD_TYPE_ADDR_AB:
                        addr_a = MONTER_SWCMD_ADDR_A(cmd);
                        addr_b = MONTER_SWCMD_ADDR_B(cmd);
                        cmd = MONTER_CMD_ADDR_AB(addr_a, addr_b, 0);

                        user_data->addr_a = addr_a;
                        user_data->addr_b = addr_b;
                        user_data->addr_set = 1;
                        break;

                    case MONTER_SWCMD_TYPE_RUN_MULT:
                        addr_d = MONTER_SWCMD_ADDR_D(cmd);
                        sizeM1 = MONTER_SWCMD_RUN_SIZE(cmd);
                        cmd = MONTER_CMD_RUN_MULT(sizeM1, addr_d, 0);
                        break;

                    case MONTER_SWCMD_TYPE_RUN_REDC:
                        addr_d = MONTER_SWCMD_ADDR_D(cmd);
                        sizeM1 = MONTER_SWCMD_RUN_SIZE(cmd);
                        cmd = MONTER_CMD_RUN_REDC(sizeM1, addr_d, 0);
                        break;
                }
                spin_lock_irqsave(&dev->dev_lock, flags);
                circ_buf_write(dev->cmd_buf, cmd);
                spin_unlock_irqrestore(&dev->dev_lock, flags);
            }

            cmds_sent += cmd_pack;
            cmds_to_send -= cmd_pack;

            /* put a counter after the commands */
            counter_index = dev->cmd_buf->end;
            cmd = MONTER_CMD_COUNTER(counter_index, 1);

            spin_lock_irqsave(&dev->dev_lock, flags);
            circ_buf_write(dev->cmd_buf, cmd);
            spin_unlock_irqrestore(&dev->dev_lock, flags);

            /* put the context with its counter on a list */
            atomic_inc(&user_data->cmd_count);
            entry->user_data = user_data;
            entry->counter = counter_index;

            spin_lock_irqsave(&dev->dev_lock, flags);
            list_add_tail(&entry->list, &dev->cmd_completion_wait_list);
            spin_unlock_irqrestore(&dev->dev_lock, flags);

            iowrite32(dev->dma_handle_cmd_buf + dev->cmd_buf->end*MONTER_CMD_SIZE,
                dev->iomap + MONTER_CMD_WRITE_PTR);

        }
        mutex_unlock(&dev->mutex);
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

    mutex_lock(&user_data->mutex);
    if (!user_data->data_block) { /* fsync before ioctl */
        printk(KERN_INFO "error in monter: fsync before ioctl\n");
        mutex_unlock(&user_data->mutex);;
        return -EINVAL;
    }
    mutex_unlock(&user_data->mutex);

    wait_event(user_data->fsync_queue, atomic_read(&user_data->cmd_count) == 0);

    return 0;
}

static int monter_release(struct inode *n, struct file *filp)
{
    struct context *user_data = filp->private_data;

    if (!user_data) {
        return 0;
    }

    wait_event(user_data->fsync_queue, atomic_read(&user_data->cmd_count) == 0);

    context_ref_count_dec(user_data);

    kfree(user_data);

    return 0;
}

/*=============== VMA OPERATIONS ============================================*/

static void context_ref_count_dec(struct context *user_data) {
    if (atomic_dec_and_test(&user_data->ref_count)) {
        dma_free_coherent(user_data->device->pdev_dev,
                          user_data->data_block_size,
                          user_data->data_block,
                          user_data->dma_handle_data_block);
    }
}

static void monter_vma_open(struct vm_area_struct *vma)
{
    struct context *user_data = vma->vm_private_data;

    atomic_inc(&user_data->ref_count);
}

static void monter_vma_close(struct vm_area_struct *vma)
{
    struct context *user_data = vma->vm_private_data;

    context_ref_count_dec(user_data);
}

/*=============== MODULE INFO ===============================================*/

module_init(monter_init);
module_exit(monter_cleanup);

MODULE_AUTHOR("Marta Rozek (mr360953@students.mimuw.edu.pl)");
MODULE_DESCRIPTION("PCI driver for Monter™ devices.");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, pci_ids);
