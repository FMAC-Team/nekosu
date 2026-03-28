#include "hashtable.h"
#include <fmac.h>

int fmac_init()
{
	int ret;
	ret = rhash_init();
	if (ret) {
		pr_err("failed to load hashtable\n");
		return ret;
	}
	return 0;
}
