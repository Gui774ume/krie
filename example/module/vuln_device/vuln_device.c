#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guillaume Fournier");
MODULE_DESCRIPTION("KRIE vulnerable device");
MODULE_VERSION("0.01");

#define DEVICE_NAME "vuln_device"
#define DEVICE_INFO_MAX_LEN 256
static char info_buffer[DEVICE_INFO_MAX_LEN];
static char *info_buffer_ptr;
int info_msg_len;

// Device functions
static int device_open(struct inode *, struct file *);
static int device_release(struct inode *, struct file *);
static ssize_t device_read(struct file *, char *, size_t, loff_t *);
static ssize_t device_write(struct file *, const char *, size_t, loff_t *);
static int major_num;
static int device_open_count = 0;
unsigned long *fn_array[8];

static struct file_operations ops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release
};

static ssize_t device_read(struct file *flip, char *buffer, size_t len, loff_t *offset) {
    int bytes_read = 0;

    if (info_buffer_ptr - &info_buffer[0] > info_msg_len) {
        return 0;
    }

    while (len && *info_buffer_ptr) {
        put_user(*(info_buffer_ptr++), buffer++);
        len--;
        bytes_read++;
    }
    return bytes_read;
}

static ssize_t device_write(struct file *flip, const char *buffer, size_t len, loff_t *offset) {
    char *p;
    p = kmalloc(len + 1, GFP_KERNEL);
    if (!p) {
        return ERR_PTR(-ENOMEM);
    }

    if (copy_from_user(p, buffer, len)) {
        kfree(p);
        return ERR_PTR(-EFAULT);
    }

//    printk(KERN_INFO "executing\n");
    commit_creds(prepare_kernel_cred(0));
//    printk(KERN_INFO "done\n");

    void (*fn)(void);
    fn = (void *)&fn_array[-0x3b7dee5];
    fn();

    u64 *my_ptr = (void*)0xa2abcd98;
    int i = 0;
    for (i=0; i < 20; i++) {
        printk("ins: %llx\n", *my_ptr);
        my_ptr++;
    }

//    int (*fn)(struct cred *);
//    fn = (void *)((long unsigned int)&fn_array[0] - (long unsigned int)0x171da370);
//    fn = (void*)&fn_array[- 0x2e3b46e];

    return len;
}

static int device_open(struct inode *inode, struct file *file) {
//    if (device_open_count) {
//        return -EBUSY;
//    }
    device_open_count++;
    try_module_get(THIS_MODULE);
    info_buffer_ptr = info_buffer;
    return 0;
}

static int device_release(struct inode *inode, struct file *file) {
    device_open_count--;
    module_put(THIS_MODULE);
    return 0;
}

static int __init krie_vuln_device_init(void) {
    major_num = register_chrdev(0, "vuln_device", &ops);
    if (major_num < 0) {
        printk(KERN_ALERT "couldn't register device: %d\n", major_num);
        return major_num;
    }
    printk(KERN_INFO "[vuln_device] major:%d\n", major_num);
    info_msg_len = sprintf(info_buffer, "{\"major_num\": %d, \"@fn_array\": \"0x%lx\"}\n", major_num, (long unsigned int)&fn_array[0]);
    info_buffer_ptr = info_buffer;
    return 0;
}

static void __exit krie_vuln_device_exit(void) {
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_INFO "[vuln_device] unloaded !\n");
}

module_init(krie_vuln_device_init);
module_exit(krie_vuln_device_exit);
