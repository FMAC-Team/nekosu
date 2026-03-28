#include <fmac.h>

int fmac_init(void)
{
	int ret;
	ret = rhash_init();
	if (ret) {
		pr_err("failed to load hashtable\n");
		return ret;
	}
	ret = load_hook();
	if (ret) {
		pr_err("failed to load hashtable\n");
		return ret;
	}
	return 0;
}
