#include <linux/cdev.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include "monter.h"

#define MONTER_MAX_DEVS (256)
#define MONTER_NAME "monter"
#define BAR0 0
#define DMA_SIZE 0

/* prototypes */
static int probe(struct pci_dev *pdev, const struct pci_device_id *id);
static void remove(struct pci_dev *pdev);

static int monter_open(struct inode *, struct file *);
static long monter_ioctl(struct file *, unsigned int, unsigned long);
static int monter_mmap(struct file *, struct vm_area_struct *);
static ssize_t monter_write(struct file *, const char __user *, size_t, loff_t *);
static int monter_fsync(struct file *, loff_t, loff_t, int datasync);
static int monter_release(struct inode *, struct file *);

static irqreturn_t intr_handler(int, void *, struct pt_regs *);
/* end prototypes */

/* for allocating minors */
static DEFINE_IDR(monter_minor_idr);

/* private struct for handling devices */
struct monter_data {
    dev_t numbers;
    struct device *device;
    struct cdev *cdev;
    void __iomem *iomap;
    dma_addr_t * dma_handle;
    void *cpu_addr;
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


static int monter_open(struct inode *inode, struct file *f)
{
    return 0;
}

static long monter_ioctl(struct file *filp, unsigned int n, unsigned long l)
{
    return 0;
}

static int monter_mmap(struct file *filp, struct vm_area_struct *area)
{
    return 0;
}

static ssize_t monter_write(struct file *f, const char __user *buff, size_t count, loff_t *fpos)
{
    return 0;
}

static int monter_fsync(struct file *f, loff_t o1, loff_t o2, int datasync)
{
    return 0;
}

static int monter_release(struct inode *n, struct file *f)
{
    return 0;
}

/* nie może blokować!!! */
static irqreturn_t irq_handler(int irq, void *dev_id, struct pt_regs *regs)
{
    /* regs - pointer to a structure containing the processor registers and state before servicing the interrupt, raczej nieużywane */
    /* return: IRQ_NONE or IRQ_HANDLED */

    return IRQ_HANDLED;
}

/* TODO konfiguracja, jakiś reset */
static int probe(struct pci_dev *pdev, const struct pci_device_id *id)
{   int ret;
    struct cdev *cdev;
    struct device *device;
    struct monter_data *data;
    void __iomem *iomap;
    dma_addr_t *dma_handle;
    void *cpu_addr;

    data = kmalloc(sizeof(data), GFP_KERNEL);
    if (IS_ERR(data)) {
        printk(KERN_INFO "error in allocating memory for monter\n");
        ret = PTR_ERR(data);
        goto out;
    }
    pci_set_drvdata(pdev, (void *) data);

    ret = idr_alloc(&monter_minor_idr, (void *) data, 0, MONTER_MAX_DEVS, GFP_KERNEL);
    if (ret < 0) {
        printk(KERN_INFO "error in allocating minor for monter\n");
        goto out_malloc;
    }
    data->numbers = MKDEV(MAJOR(first_dev), ret);

    cdev = cdev_alloc();
    if (IS_ERR(cdev)) {
        printk(KERN_INFO "error in allocating char device for monter\n");
        ret = PTR_ERR(cdev);
        goto out_idr;
    }

    cdev->owner = THIS_MODULE;
    cdev->ops = &monter_fops;
    ret = cdev_add(cdev, data->numbers, 1);
    if (ret < 0) {
        printk(KERN_INFO "error in adding char device for monter\n");
        goto out_cdev;
    }
    data->cdev = cdev;

    device = device_create(monter_class, &(pdev->dev), data->numbers, 0, "%s%d", MONTER_NAME, MINOR(data->numbers));
    if (IS_ERR(device)) {
        printk(KERN_INFO "error in creating device for monter\n");
        ret = PTR_ERR(device);
        goto out_cdev;
    }
    data->device = device;

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

    iomap = pci_iomap(pdev, BAR0, 0);
    if (IS_ERR(iomap)) {
        printk(KERN_INFO "error in iomap for monter\n");
        ret = PTR_ERR(iomap);
        goto out_regions;
    }
    data->iomap = iomap;

    pci_set_master(pdev);

    ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(32));
    if (ret < 0) {
        printk(KERN_INFO "error in setting dma mask for monter\n");
        goto out_master;
    }

    ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(32));
    if (ret < 0) {
        printk(KERN_INFO "error in setting dma mask for monter\n");
        goto out_master;
    }

    cpu_addr = dma_alloc_coherent(&pdev->dev, DMA_SIZE, dma_handle, GFP_ATOMIC); /* TODO sprawdzić flagi */
    if (IS_ERR(cpu_addr)) {
        printk(KERN_INFO "error in iomap for monter\n");
        ret = PTR_ERR(iomap);
        goto out_master;
    }
    data->cpu_addr = cpu_addr;
    data->dma_handle = dma_handle;

    ret = request_irq(pdev->irq, irq_handler, IRQF_SHARED, MONTER_NAME, pdev);   /* TODO upewnić się że nie ma wiszących przerwań */
    if (ret < 0) {                                                               /* TODO sprawdzić czy name nie musi być z minorem */
        printk(KERN_INFO "error in registering interrupt handler for monter\n"); /* TODO sprawdzić czy pdev to dobry unikalny struct w request_irq
                                                                                  *  podobno zwykle używa się device */
        goto out_dma;
    }


    printk(KERN_INFO "probe successful for monter\n");
    ret = 0;
    goto out;

out_dma:
    dma_free_coherent(&pdev->dev, DMA_SIZE, cpu_addr, dma_handle);
out_master:
    pci_clear_master(pdev);
out_iomap:
    pci_iounmap(pdev, data->iomem);
out_regions:
    pci_release_regions(pdev);  /* TODO najpierw disable, potem release */
out_enable:
    pci_disable_device(pdev);
out_device:
    device_destroy(monter_class, data->numbers);
out_cdev:
    cdev_del(cdev);
out_idr:
    idr_remove(&monter_minor_idr, MINOR(data->numbers));
out_malloc:
    kfree(data);
out:
    return ret;
}

/* TODO sprawdzić kolejność */
static void remove(struct pci_dev *pdev)
{
    struct monter_data *data;

    pci_disable_device(pdev);  /* w dokumentacji PCI najpierw disable, potem release */
    pci_release_regions(pdev);
    free_irq(pdev->irq, (void *) pdev); /* TODO upewnić się że monter już nie zgłosi przerwań */

    data = pci_get_drvdata(pdev);
    if (IS_ERR(data)) {
        printk(KERN_INFO "can't retrieve monter's data\n");
        return;
    }

    dma_free_coherent(&pdev->dev, DMA_SIZE, data->cpu_addr, data->dma_handle);
    pci_iounmap(pdev, data->iomem);
    device_destroy(monter_class, data->numbers);
    cdev_del(data->cdev);
    idr_remove(&monter_minor_idr, MINOR(data->numbers));
    kfree(data);

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
    if (IS_ERR(monter_class)) {
        printk(KERN_INFO "error in creating class for monter\n");
        ret = PTR_ERR(monter_class);
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


module_init(monter_init);
module_exit(monter_cleanup);

MODULE_AUTHOR("Marta Rozek (mr360953@students.mimuw.edu.pl)");
MODULE_DESCRIPTION("PCI driver for MONTER devices.");
MODULE_LICENSE("GPL");
MODULE_DEVICE_TABLE(pci, pci_ids);
