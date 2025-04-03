#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/syscalls.h>
#include "kshram.h"
#define DEVICE_COUNT 8
#define DEFAULT_SIZE 4096
#define KSHRAM_DEV_PERMISSIONS 0666

static ssize_t mode_show(struct class *class, struct class_attribute *attr, char *buf) {
    return 0;
}

static ssize_t mode_store(struct class *class, struct class_attribute *attr, const char *buf, size_t count) {
    return count;
}

static CLASS_ATTR_RW(mode);


struct kshram_dev {
	struct cdev cdev;
	void *data;
	size_t size;
	struct proc_dir_entry *proc_entry;
	int idx;
};

static dev_t devnum;
static struct class *clazz;
static struct kshram_dev kshram_devices[DEVICE_COUNT];


// ioctl function
static long kshram_ioctl(struct file *filp, unsigned int cmd, unsigned long arg) {
	struct kshram_dev *dev = filp->private_data;
    void *new_data;
	size_t new_size;

	switch (cmd) {
		case KSHRAM_GETSLOTS:
			return DEVICE_COUNT;

		case KSHRAM_GETSIZE:
			return dev->size;

		case KSHRAM_SETSIZE:
			new_size = (size_t)arg;
			new_data = krealloc(dev->data, new_size, GFP_KERNEL);
			if (new_data == NULL)
				return -ENOMEM;
			dev->data = new_data;
			dev->size = new_size;
			return 0;

		default:
			return -EINVAL;
	}
}

// Open function
static int kshram_open(struct inode *inode, struct file *filp) {
    int minor = iminor(inode);
    if (minor >= DEVICE_COUNT) {
        return -ENODEV;
    }

    filp->private_data = &kshram_devices[minor];
    return 0;
}

// Release function
static int kshram_release(struct inode *inode, struct file *filp) {
    return 0;
}

// Mmap function
static int kshram_mmap(struct file *filp, struct vm_area_struct *vma) {
    struct kshram_dev *dev = filp->private_data;
    unsigned long pfn = vmalloc_to_pfn(dev->data);
    unsigned long size = vma->vm_end - vma->vm_start;

	printk(KERN_INFO "kshram/mmap: idx %d size %ld\n", dev->idx, size);

    if (size > dev->size) {
        return -EINVAL;
    }

    if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
        return -EAGAIN;
    }

    return 0;
}

static ssize_t kshram_proc_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    int i, len=0;
    char output[256] = "";

    for (i = 0; i < DEVICE_COUNT; i++)
    {
        len += sprintf(output + len, "%02d: %zu\n", i, kshram_devices[i].size);
    }

    return simple_read_from_buffer(buf, count, ppos, output, len);
}


static const struct file_operations kshram_fops = {
    .owner = THIS_MODULE,
    .open = kshram_open,
    .release = kshram_release,
    .unlocked_ioctl = kshram_ioctl,
    .mmap = kshram_mmap,
};

static const struct proc_ops kshram_proc_fops = {
    .proc_read = kshram_proc_read,
};

static char *kshram_devnode(const struct device *dev, umode_t *mode) {
	if(mode == NULL) return NULL;
	*mode = 0666;
	return NULL;
}

static int __init kshram_init(void) {
	int err, i, ret;

	// const struct device_attribute dev_attr_perms = __ATTR(mode, S_IWUSR | S_IRUGO, NULL, NULL);
	err = alloc_chrdev_region(&devnum, 0, DEVICE_COUNT, "kshram");
	if (err < 0)
		return err;

	clazz = class_create(THIS_MODULE, "kshram");
	if (IS_ERR(clazz)) {
		err = PTR_ERR(clazz);
		goto out_unregister_chrdev;
	}
	clazz->devnode = kshram_devnode;

	//設置權限
	ret = class_create_file(clazz, &class_attr_mode);


	if (ret < 0) {
		printk(KERN_ERR "kshram: failed to create class attribute file\n");
		class_destroy(clazz);
		return ret;
	}

	for (i = 0; i < DEVICE_COUNT; i++) {
		struct kshram_dev *dev = &kshram_devices[i];
		struct device *kshram_device;
		if(i==0)
			dev->proc_entry = proc_create_data("kshram", 0, NULL, &kshram_proc_fops, dev);

		cdev_init(&dev->cdev, &kshram_fops);
		dev->cdev.owner = THIS_MODULE;

		err = cdev_add(&dev->cdev, devnum + i, 1);
		if (err) {
			goto out_cleanup_cdevs;
		}

		kshram_device = device_create(clazz, NULL, devnum + i, NULL, "kshram%d", i);


		dev->data = kzalloc(DEFAULT_SIZE, GFP_KERNEL);
		if (dev->data == NULL) {
			err = -ENOMEM;
			goto out_cleanup_cdevs;
		}
		dev->size = DEFAULT_SIZE;
		dev->idx = i;
		printk(KERN_INFO "kshram%d: %d bytes allocated @ %px\n", i, DEFAULT_SIZE, dev->data);
	}
	printk(KERN_INFO "kshram: initialized.\n");

	return 0;

out_cleanup_cdevs:
	while (--i >= 0) {
		struct kshram_dev *dev = &kshram_devices[i];
		device_destroy(clazz, devnum + i);
		cdev_del(&dev->cdev);
		kfree(dev->data);
	}
	class_destroy(clazz);

out_unregister_chrdev:
	unregister_chrdev_region(devnum, DEVICE_COUNT);
	return err;
}

static void __exit kshram_exit(void) {
	int i;
	struct kshram_dev *dev;
	for (i = 0; i < DEVICE_COUNT; i++) {
		dev = &kshram_devices[i];
		device_destroy(clazz, devnum + i);
		if (dev->data) {
			kfree(dev->data);
		}
		if (i==0 && dev->proc_entry) {
			proc_remove(dev->proc_entry);
		}
		cdev_del(&dev->cdev);
	}
	class_remove_file(clazz, &class_attr_mode);

	class_destroy(clazz);
	unregister_chrdev_region(devnum, DEVICE_COUNT);
	printk(KERN_INFO "kshram: cleaned up.\n");
}

module_init(kshram_init);
module_exit(kshram_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("SCI");
MODULE_DESCRIPTION("kshram kernel module");
