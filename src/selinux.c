#include "security.h"
#include "ss/symtab.h"
#include "ss/policydb.h"
#include "ss/ebitmap.h"
#include "ss/services.h"
#include "objsec.h"

#include <fmac.h>

#define DOMAIN "su"

void setenforce(bool status)
{
// true or false
#ifdef CONFIG_SECURITY_SELINUX_DEVELOP
	selinux_state.enforcing = status;
#endif
}

bool do_allow(struct policydb *db, const char *type_name)
{
	struct type_datum *type;
	bool permissive = true;
	type = (struct type_datum *)symtab_search(&db->p_types, type_name);
	if (type == NULL) {
		pr_err("type null,do_allow false\n");
		return false;
	}
	if (ebitmap_set_bit(&db->permissive_map, type->value, permissive)) {
		pr_err("can't set bitmap\n");
		return false;
	}
	return true;
}

int set_domain(const char *domain, struct cred *new_cred)
{
	u32 newsid;
	int rc;

	rc = security_context_to_sid(&selinux_state, domain, strlen(domain),
				     &newsid, GFP_KERNEL);
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

void init_selinux_hook(void)
{
	struct policydb *db;
	if (!selinux_state.policy)
		return;

	db = &selinux_state.policy->policydb;
	setenforce(true);

	if (do_allow(db, DOMAIN)) {
		pr_info("set permissive\n");
	}

}
