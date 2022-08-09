#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <linux/device.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Guillaume Fournier");
MODULE_DESCRIPTION("KRIE vulnerable device");
MODULE_VERSION("0.01");

/* The system call table (a table of functions). We
 * just define this as external, and the kernel will
 * fill it up for us when we are insmod'ed
 */
u64 *sys_call_table;

unsigned long original_cr0;
extern unsigned long __force_order;

static inline void write_forced_cr0(unsigned long val) {
    asm volatile("mov %0,%%cr0":"+r" (val), "+m"(__force_order));
};

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
static long device_ioctl(struct file *, unsigned int, unsigned long);
static struct class *class;
static int major_num;
static int device_open_count = 0;
unsigned long *fn_array[8];

static struct file_operations ops = {
    .read = device_read,
    .write = device_write,
    .open = device_open,
    .release = device_release,
	.unlocked_ioctl = device_ioctl
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

struct ioctl_req {
	unsigned long offset;
};

static long device_ioctl(struct file *file, unsigned int cmd, unsigned long args) {
	struct ioctl_req *req;
	void (*fn)(void);

	switch(cmd) {
	case 0:
		req = (struct ioctl_req *)args;
//		printk(KERN_INFO "ioctl offset = %lx\n", req->offset);
		fn = (void *)&fn_array[0] - req->offset;
//        printk(KERN_INFO "jumping now to 0x%lx\n", (void*)fn);
		fn();
		break;
	default:
		break;
	}

	return 0;
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

//    printk(KERN_INFO "executing commit_creds\n");
//    commit_creds(prepare_kernel_cred(0));
//    printk(KERN_INFO "done\n");

    return len;
}

static int device_open(struct inode *inode, struct file *file) {
    if (device_open_count) {
        return -EBUSY;
    }
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

/* A pointer to the original system call. The reason
 * we keep this, rather than call the original function
 * (sys_open), is because somebody else might have
 * replaced the system call before us. Note that this
 * is not 100% safe, because if another module
 * replaced sys_open before us, then when we're inserted
 * we'll call the function in that module - and it
 * might be removed before we are.
 *
 * Another reason for this is that we can't get sys_open.
 * It's a static variable, so it is not exported. */
asmlinkage int (*original_call)(const char *, int, int);

/* The function we'll replace sys_open (the function
 * called when you call the open system call) with. To
 * find the exact prototype, with the number and type
 * of arguments, we find the original function first
 * (it's at fs/open.c).
 *
 * In theory, this means that we're tied to the
 * current version of the kernel. In practice, the
 * system calls almost never change (it would wreck havoc
 * and require programs to be recompiled, since the system
 * calls are the interface between the kernel and the
 * processes).
 */
asmlinkage int our_sys_open(const char *filename,
                            int flags,
                            int mode)
{
    printk(KERN_ALERT "open !!\n");
    /* Call the original sys_open - otherwise, we lose
    * the ability to open files */
    return original_call(filename, flags, mode);
}

static int __init krie_vuln_device_init(void) {
    major_num = register_chrdev(0, DEVICE_NAME, &ops);
    if (major_num < 0) {
        printk(KERN_ALERT "couldn't register device: %d\n", major_num);
        return major_num;
    }

    printk(KERN_INFO "[vuln_device] major:%d\n", major_num);
    info_msg_len = sprintf(info_buffer, "{\"major_num\": %d, \"@fn_array\": \"0x%lx\"}\n", major_num, (long unsigned int)&fn_array[0]);
    info_buffer_ptr = info_buffer;

	class = class_create(THIS_MODULE, DEVICE_NAME);
	device_create(class, NULL, MKDEV(major_num, 0), NULL, DEVICE_NAME);

//    sys_call_table = (u64 *)0xffffffff91c00300;
//
//    // disable write_protect and hook syscall
//    original_cr0 = read_cr0();
//    printk(KERN_INFO "write_protect: %d\n", (original_cr0 & 0x10000) == 0x10000);
//    write_forced_cr0(original_cr0 & ~0x10000);
//    /* Keep a pointer to the original function in
//    * original_call, and then replace the system call
//    * in the system call table with our_sys_open */
//    original_call = sys_call_table[__NR_open];
//    sys_call_table[__NR_open] = our_sys_open;
//    write_forced_cr0((original_cr0 | 0x10000));
//
//    printk(KERN_INFO "open is at 0x%x\n", original_call);
//    printk(KERN_INFO "jumping to 0x%x\n", our_sys_open);

    return 0;
}

static void __exit krie_vuln_device_exit(void) {
	device_destroy(class, MKDEV(major_num, 0));
	class_unregister(class);
	class_destroy(class);
    unregister_chrdev(major_num, DEVICE_NAME);
    printk(KERN_INFO "[vuln_device] unloaded !\n");

//    /* Return the system call back to normal */
//    if (sys_call_table[__NR_open] == our_sys_open) {
//        write_forced_cr0(original_cr0 & ~0x10000);
//        sys_call_table[__NR_open] = original_call;
//        write_forced_cr0((original_cr0 | 0x10000));
//    }

}

module_init(krie_vuln_device_init);
module_exit(krie_vuln_device_exit);
