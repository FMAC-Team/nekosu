#include <linux/fs.h>
#include <linux/uaccess.h>
#include <fmac.h>

#define IOC_MAGIC      'F'
#define IOC_GET_SHM    _IO(IOC_MAGIC,  0)
#define IOC_BIND_EVT   _IOW(IOC_MAGIC, 1, int)
#define IOC_CHK_WRITE  _IOR(IOC_MAGIC, 2, int)
#define FMAC_IOC_ADD_UID   _IOW(FMAC_IOC_MAGIC, 3, unsigned int)
#define FMAC_IOC_DEL_UID   _IOW(FMAC_IOC_MAGIC, 4, unsigned int)
#define FMAC_IOC_HAS_UID   _IOWR(FMAC_IOC_MAGIC, 5, unsigned int)

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
	case FMAC_IOC_ADD_UID:{
			unsigned int id;
			if (copy_from_user
			    (&id, (unsigned int __user *)arg, sizeof(id)))
				return -EFAULT;
			if (id > MAX_UID)
				return -EINVAL;
			set_bit(id, uid_bitmap);
			return 0;
		}

	case FMAC_IOC_DEL_UID:{
			unsigned int id;
			if (copy_from_user
			    (&id, (unsigned int __user *)arg, sizeof(id)))
				return -EFAULT;
			if (id > MAX_UID)
				return -EINVAL;
			clear_bit(id, uid_bitmap);
			return 0;
		}

	case FMAC_IOC_HAS_UID:{
			unsigned int id;
			if (copy_from_user
			    (&id, (unsigned int __user *)arg, sizeof(id)))
				return -EFAULT;
			if (id > MAX_UID)
				return -EINVAL;
			id = test_bit(id, uid_bitmap) ? 1 : 0;
			if (copy_to_user
			    ((unsigned int __user *)arg, &id, sizeof(id)))
				return -EFAULT;
			return 0;
		}

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
