#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/anon_inodes.h>
#include <fmac.h>
#include "uid_caps.h"

struct fmac_rule {
	char path[1024];
	unsigned long status_bits;
};

struct fmac_uid_cap {
	unsigned int uid;
	uint64_t caps;
};

struct fmac_sepolicy_rule {
	char src[64];
	char tgt[64];
	char cls[64];
	char perm[64];
	int effect;
	int invert;
};

#define IOC_MAGIC         'F'
#define IOC_GET_SHM       _IO(IOC_MAGIC,    0)
#define IOC_BIND_EVT      _IOW(IOC_MAGIC,   1, int)
#define IOC_CHK_WRITE     _IOR(IOC_MAGIC,   2, int)
#define IOC_ADD_UID       _IOW(IOC_MAGIC,   3, unsigned int)
#define IOC_DEL_UID       _IOW(IOC_MAGIC,   4, unsigned int)
#define IOC_HAS_UID       _IOWR(IOC_MAGIC,  5, unsigned int)
#define IOC_SET_CAP       _IOW(IOC_MAGIC,   6, struct fmac_uid_cap)
#define IOC_GET_CAP       _IOWR(IOC_MAGIC,  7, struct fmac_uid_cap)
#define IOC_DEL_CAP       _IOW(IOC_MAGIC,   8, struct fmac_uid_cap)
#define IOC_SEL_ADD_RULE  _IOW(IOC_MAGIC,   9, struct fmac_sepolicy_rule)

static long ioc_add_uid(unsigned long arg)
{
	unsigned int id;
	if (copy_from_user(&id, (unsigned int __user *)arg, sizeof(id)))
		return -EFAULT;
	return nksu_profile_set_default((uid_t)id) ? -ENOMEM : 0;
}

static long ioc_del_uid(unsigned long arg)
{
	unsigned int id;
	if (copy_from_user(&id, (unsigned int __user *)arg, sizeof(id)))
		return -EFAULT;
	return nksu_profile_clear((uid_t)id) ? -ENOENT : 0;
}

static long ioc_has_uid(unsigned long arg)
{
	unsigned int id;
	if (copy_from_user(&id, (void __user *)arg, sizeof(id)))
		return -EFAULT;
	id = nksu_profile_has_uid((uid_t)id) ? 1 : 0;
	if (copy_to_user((void __user *)arg, &id, sizeof(id)))
		return -EFAULT;
	return 0;
}

static long ioc_set_cap(unsigned long arg)
{
	struct fmac_uid_cap uc;
	if (copy_from_user(&uc, (struct fmac_uid_cap __user *)arg, sizeof(uc)))
		return -EFAULT;
	if (uid_caps_has_uid(uc.uid))
		return uid_caps_update(uc.uid, uc.caps) ? -EINVAL : 0;
	return uid_caps_add(uc.uid, uc.caps) ? -EINVAL : 0;
}

static long ioc_get_cap(unsigned long arg)
{
	struct fmac_uid_cap uc;
	if (copy_from_user(&uc, (struct fmac_uid_cap __user *)arg, sizeof(uc)))
		return -EFAULT;
	if (!uid_caps_has_uid(uc.uid))
		return -ENOENT;
	uc.caps = uid_caps_get(uc.uid);
	return copy_to_user((struct fmac_uid_cap __user *)arg, &uc, sizeof(uc))
		? -EFAULT : 0;
}

static long ioc_del_cap(unsigned long arg)
{
	struct fmac_uid_cap uc;
	if (copy_from_user(&uc, (struct fmac_uid_cap __user *)arg, sizeof(uc)))
		return -EFAULT;
	return uid_caps_remove(uc.uid) ? -ENOENT : 0;
}

static long ioc_sel_add_rule(unsigned long arg)
{
	struct fmac_sepolicy_rule r;
	if (copy_from_user(&r, (void __user *)arg, sizeof(r)))
		return -EFAULT;
	r.src[sizeof(r.src) - 1] = '\0';
	r.tgt[sizeof(r.tgt) - 1] = '\0';
	r.cls[sizeof(r.cls) - 1] = '\0';
	r.perm[sizeof(r.perm) - 1] = '\0';
	return sepolicy_add_rule(r.src[0] ? r.src : NULL,
				 r.tgt[0] ? r.tgt : NULL,
				 r.cls[0] ? r.cls : NULL,
				 r.perm[0] ? r.perm : NULL,
				 r.effect, (bool)r.invert);
}

static long fmac_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	switch (cmd) {
	case IOC_GET_SHM:
		ret = fmac_anonfd_get();
		break;

	case IOC_BIND_EVT: {
		int efd;
		if (copy_from_user(&efd, (int __user *)arg, sizeof(efd)))
			return -EFAULT;
		ret = bind_eventfd(efd);
		break;
	}

	case IOC_CHK_WRITE: {
		int changed = check_mmap_write() ? 1 : 0;
		if (copy_to_user((int __user *)arg, &changed, sizeof(changed)))
			return -EFAULT;
		break;
	}

	case IOC_ADD_UID:
		return ioc_add_uid(arg);
	case IOC_DEL_UID:
		return ioc_del_uid(arg);
	case IOC_HAS_UID:
		return ioc_has_uid(arg);
	case IOC_SET_CAP:
		return ioc_set_cap(arg);
	case IOC_GET_CAP:
		return ioc_get_cap(arg);
	case IOC_DEL_CAP:
		return ioc_del_cap(arg);
	case IOC_SEL_ADD_RULE:
		return ioc_sel_add_rule(arg);
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