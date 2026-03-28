#include "hashtable.h"

int fmac_check_openat(const char *pathname)
{
	if (check_node_bit(pathname, FMAC_BIT_DENY)) {
		return -EACCES;
	}
	if (check_node_bit(pathname, FMAC_BIT_NOT_FOUND)) {
		return -ENOENT;
	}
	return 0;
}
