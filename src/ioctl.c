#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/anon_inodes.h>
#include <fmac.h>

// no export
struct fmac_rule {
	char path[1024];
	unsigned long status_bits;
};

#define IOC_MAGIC      'F'
#define IOC_GET_SHM    _IO(IOC_MAGIC,  0)
#define IOC_BIND_EVT   _IOW(IOC_MAGIC, 1, int)
#define IOC_CHK_WRITE  _IOR(IOC_MAGIC, 2, int)
#define IOC_ADD_UID   _IOW(IOC_MAGIC, 3, unsigned int)
#define IOC_DEL_UID   _IOW(IOC_MAGIC, 4, unsigned int)
#define IOC_HAS_UID   _IOWR(IOC_MAGIC, 5, unsigned int)

if (IS_ENABLED(CONFIG_FMAC_SYSCALL)) {
#define IOC_ADD_RULE  _IOW(IOC_MAGIC, 6, struct fmac_rule)
#define IOC_DEL_RULE  _IOW(IOC_MAGIC, 7, struct fmac_rule)
}

static long ioc_has_uid(unsigned long arg)
{
	unsigned int id;
	if (copy_from_user(&id, (unsigned int __user *)arg, sizeof(id)))
		return -EFAULT;
	id = fmac_uid_has(id) ? 1 : 0;
	return copy_to_user((unsigned int __user *)arg, &id, sizeof(id))
	    ? -EFAULT : 0;
}

static long fmac_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case IOC_GET_SHM:
		ret = fmac_anonfd_get();
		break;

	case IOC_BIND_EVT:{
			int efd;
			if (copy_from_user
			    (&efd, (int __user *)arg, sizeof(efd)))
				return -EFAULT;
			ret = bind_eventfd(efd);
			break;
		}

	case IOC_CHK_WRITE:{
			int changed = check_mmap_write()? 1 : 0;
			if (copy_to_user
			    ((int __user *)arg, &changed, sizeof(changed)))
				return -EFAULT;
			break;
		}
	case IOC_ADD_UID:{
			unsigned int id;
			if (copy_from_user
			    (&id, (unsigned int __user *)arg, sizeof(id)))
				return -EFAULT;
			add_uid(id);
			return 0;
		}

	case IOC_DEL_UID:{
			unsigned int id;
			if (copy_from_user
			    (&id, (unsigned int __user *)arg, sizeof(id)))
				return -EFAULT;
			del_uid(id);
			return 0;
		}
		if (IS_ENABLED(CONFIG_FMAC_SYSCALL)) {
	case IOC_ADD_RULE:{
				struct fmac_rule rule;
				if (copy_from_user
				    (&rule, (struct fmac_rule __user *)arg,
				     sizeof(rule)))
					return -EFAULT;
				rule.path[sizeof(rule.path) - 1] = '\0';
				insert_into_hash_table(rule.path,
						       rule.status_bits);
				return 0;
			}

	case IOC_DEL_RULE:{
				struct fmac_rule rule;
				if (copy_from_user
				    (&rule, (struct fmac_rule __user *)arg,
				     sizeof(rule)))
					return -EFAULT;
				rule.path[sizeof(rule.path) - 1] = '\0';
				delete_from_hash_table(rule.path);
				return 0;
			}
		}
	case IOC_HAS_UID:
		return ioc_has_uid(arg);

	default:
		return -ENOTTY;
	}

	return ret;
}

static const struct file_operations fmac_ctl_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = fmac_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = fmac_ioctl,
#endif
};

int fmac_ctlfd_get(void)
{
	return anon_inode_getfd("[fmac_ctl]", &fmac_ctl_fops, NULL,
				O_RDWR | O_CLOEXEC);
}
