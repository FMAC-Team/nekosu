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

tsec->osid = tsec->sid;
tsec->sid = newsid;
tsec->exec_sid = 0;
tsec->create_sid = 0;
tsec->keycreate_sid = 0;
tsec->sockcreate_sid = 0;
		return 0;
	}

	return -EPERM;

}

bool do_allow(struct policydb *db, const char *type_name)
{
       struct type_datum *type;
      type = (struct type_datum *)symtab_search(&db->p_types, type_name);
       if (type == NULL) {
               pr_err("type null,do_allow false\n");
               return false;
       }
       if (ebitmap_set_bit(&db->permissive_map, type->value, true)) {
               pr_err("can't set bitmap\n");
               return false;
      }
      return true;
}

int __init init_selinux_hook(void)
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
	// do_allow(db,DOMAIN);
    rc = sepolicy_init();
	if (rc) {
		pr_err("Failed to apply rules 'nksu': %d\n", rc);
		return rc;
	}
	return 0;
}
