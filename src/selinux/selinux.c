#include "security.h"
#include "ss/symtab.h"
#include "ss/policydb.h"
#include "ss/ebitmap.h"
#include "ss/services.h"
#include "objsec.h"

#include <fmac.h>

#define DOMAIN "nksu"

void setenforce(bool status)
{
// true or false
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	//selinux_state.enforcing = status;
	WRITE_ONCE(selinux_state.enforcing, status);
#endif
}

bool getenforce(void)
{
	return READ_ONCE(selinux_state.enforcing);
}

int set_domain(const char *domain, struct cred *new_cred)
{
	u32 newsid;
	int rc;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 6, 0)
	rc = security_context_to_sid(domain, strlen(domain),
				     &newsid, GFP_KERNEL);
#else
	rc = security_context_to_sid(&selinux_state, domain, strlen(domain),
				     &newsid, GFP_KERNEL);
#endif

	if (rc) {
		pr_err("Failed to get SID for %s: %d\n", domain, rc);
		return rc;
	}

	if (new_cred->security) {
		struct task_security_struct *tsec = new_cred->security;
		tsec->sid = newsid;
		// tsec->osid = newsid; 
		return 0;
	}

	return -EPERM;

}

int init_selinux_hook(void)
{
	struct policydb *db;
	int rc;
	if (!selinux_state.policy)
		return -1;

	db = &selinux_state.policy->policydb;
	if (!getenforce()) {
		pr_info("[selinux]: enforcing is false,set 1\n");
		setenforce(true);
	}
	rc = sepolicy_add_domain(DOMAIN);
	if (rc) {
		pr_err("Failed to add domain 'nksu': %d\n", rc);
		return rc;
	}
	return 0;
}
