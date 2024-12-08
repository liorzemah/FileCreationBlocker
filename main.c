#define DEBUG /* for enable pr_debug write into dmesg */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/dcache.h>
#include <linux/namei.h>
#include <linux/slab.h>  // kmalloc and kfree


#define WATCHED_DIR "/home"
#define SUCCESS 0

static const struct inode_operations *original_inode_ops;
static struct inode_operations *custom_inode_ops; // Dynamically allocated for hooking

/* Custom create function */
/* default umode_t permission is 666, but after concat with the default umask the result will be 644 permission for file creation*/
static int custom_create(struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
    pr_debug("Custom create operation triggered for file: %s, mode: %d\n", dentry->d_name.name, mode);

    if (strstr(dentry->d_name.name, "malicious") != NULL)
    {
        pr_debug("Block file: %s\n", dentry->d_name.name);
        /* Block file creation, eturn permission denied error */
        return -EPERM;
    }   

    pr_debug("Create file: %s\n", dentry->d_name.name);
    /* it's not a malicause file so call the original creation method */
    return original_inode_ops->create(dir, dentry, mode, excl);
}

/* Copy inode_operations strcut, the funciton handle memory allocation */
static int copy_inode_operations_struct(struct inode_operations** dst, const struct inode_operations* src)
{
    if (*dst)
    {
        pr_err("copy_inode_operations_struct can only copy to an unallocated pointer\n");
        return -EINVAL; 
    }

    pr_info("Allocate memory for a custom inode_operations structure and copy the original\n");
    /* Allocate memory for a custom inode_operations structure and copy the original */
    *dst = kzalloc(sizeof(struct inode_operations), GFP_KERNEL);
    if (!*dst) {
        pr_err("Failed to allocate memory for custom inode operations\n");
        return -ENOMEM;
    }

    memcpy(*dst, src, sizeof(struct inode_operations));   
    return SUCCESS; 
}

static int hook_inode_ops(const char *path)
{
    struct path resolved_path;
    struct inode *inode;
    int err = SUCCESS;

    if (kern_path(path, LOOKUP_FOLLOW, &resolved_path) != SUCCESS) {
        pr_err("Failed to find the specified path: %s\n", path);
        return -ENOENT;
    }

    inode = resolved_path.dentry->d_inode;

    // Store the original inode operations
    original_inode_ops = inode->i_op;
    err = copy_inode_operations_struct(&custom_inode_ops, original_inode_ops);
    if (err != SUCCESS)
    {
        pr_err("Failed to copy inode_operations struct with err: %d\n", err);
        path_put(&resolved_path);  /* Cleanup */
        return err;
    }

    if (original_inode_ops->create) 
    {
        custom_inode_ops->create = custom_create;  /* Replace the create operation */
        pr_info("Custom create hooked.\n");
    }
    else 
    {
        pr_err("Original create operation is NULL. cannot hook custom create.\n");
        kfree(custom_inode_ops);
        path_put(&resolved_path);  /* Cleanup */
        return -ENXIO;
    }

    custom_inode_ops->create = custom_create;  /* Replace the create operation */

    /* Assign the custom inode_operations to the directory inode */
    inode->i_op = custom_inode_ops;

    path_put(&resolved_path);  /* Cleanup */
    pr_info("Original inode operations address: %p\n", original_inode_ops);
    pr_info("Custom inode operations address: %p\n", custom_inode_ops);
    pr_info("Hooked inode operations for directory: %s\n", path);
    return 0;
}

/* Restore the original inode operations */
static void unhook_inode_ops(const char *path)
{
    struct path resolved_path;
    struct inode *inode;

    if (kern_path(path, LOOKUP_FOLLOW, &resolved_path) != SUCCESS) {
        pr_err("Failed to find the specified path: %s\n", path);
        return;
    }

    inode = resolved_path.dentry->d_inode;

    if (inode->i_op == custom_inode_ops) {
        inode->i_op = original_inode_ops; /* Restore original inode_operations */
        if (custom_inode_ops)
        {
            kfree(custom_inode_ops);  /* Free the custom structure */
            custom_inode_ops = NULL;  /* Avoid dangling pointer */
        }
        pr_info("Restored original inode operations for directory: %s\n", path);
    }

    path_put(&resolved_path);  /* Cleanup */
}

static int __init my_module_init(void)
{
    int rv;
    pr_info("Loading module to intercept file creation under %s direcgtory\n", WATCHED_DIR);
    
    rv = hook_inode_ops(WATCHED_DIR);
    if (rv != SUCCESS) 
    {
        pr_err("Failed to hook inode operations\n");
        return rv;
    }

    pr_info("Module loaded and start listening to %s directory\n", WATCHED_DIR);
    return 0;
}

static void __exit my_module_exit(void)
{
    unhook_inode_ops(WATCHED_DIR);
    pr_info("Module unloaded and original operations restored.\n");
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Lior Zemah");
MODULE_DESCRIPTION("A kernel module to block file creation in a directory.");
