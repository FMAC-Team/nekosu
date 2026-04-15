#ifndef IOCTL_H
#define IOCTL_H

#define IOC_MAGIC      'F'
#define IOC_GET_SHM    _IO(IOC_MAGIC,   0)
#define IOC_BIND_EVT   _IOW(IOC_MAGIC,  1, int)
#define IOC_CHK_WRITE  _IOR(IOC_MAGIC,  2, int)
#define IOC_ADD_UID    _IOW(IOC_MAGIC,  3, unsigned int)
#define IOC_DEL_UID    _IOW(IOC_MAGIC,  4, unsigned int)
#define IOC_HAS_UID    _IOWR(IOC_MAGIC, 5, unsigned int)
#define IOC_SET_CAP    _IOW(IOC_MAGIC,  6, struct fmac_uid_cap)
#define IOC_GET_CAP    _IOWR(IOC_MAGIC, 7, struct fmac_uid_cap)
#define IOC_DEL_CAP    _IOW(IOC_MAGIC, 8, struct fmac_uid_cap)

int fmac_ctlfd_get(void);

#endif /* IOCTL_H */