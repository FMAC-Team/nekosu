#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <fmac.h>
#include <linux/slab.h>
#include <linux/mutex.h>

#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/avtab.h"
#include "avc.h"
#include "ss/symtab.h"
#include "ss/policydb.h"
#include "security.h"
#include "avc_ss.h"
#include "xfrm.h"
#include "ss/hashtab.h"

#ifndef hashtab_for_each
#define hashtab_for_each(h, node) \
    for (int i = 0; i < (h).size; i++) \
        for (node = (h).htable[i]; node; node = node->next)
#endif

static struct policydb *fmac_get_pdb(void)
{
	if (!selinux_state.policy)
		return NULL;
	return &rcu_dereference_protected(selinux_state.policy,
					  lockdep_is_held
					  (&selinux_state.policy_mutex)
	    )->policydb;
}

static void avc_reset(void)
{
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0))
	avc_ss_reset(0);
	selnl_notify_policyload(0);
	selinux_status_update_policyload(0);
#else
	avc_ss_reset(selinux_state.avc, 0);
	selnl_notify_policyload(0);
	selinux_status_update_policyload(&selinux_state, 0);
#endif
	selinux_xfrm_notify_policyload();
}

int sepolicy_add_rule(const char *sname, const char *tname,
		      const char *cname, const char *pname,
		      int effect, bool invert)
{
	struct policydb *pdb;
	struct type_datum *src = NULL, *tgt = NULL;
	struct class_datum *cls = NULL;
	struct perm_datum *perm = NULL;
	struct avtab_key key;
	struct avtab_datum datum;
	struct avtab_node *node;
	int ret = 0;

	mutex_lock(&selinux_state.policy_mutex);

	pdb = fmac_get_pdb();
	if (!pdb) {
		ret = -ENOENT;
		goto out;
	}

	if (sname && *sname) {
		src = symtab_search(&pdb->symtab[SYM_TYPES], sname);
		if (!src) {
			pr_warn("[selinux]: source type '%s' not found\n",
				sname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (tname && *tname) {
		tgt = symtab_search(&pdb->symtab[SYM_TYPES], tname);
		if (!tgt) {
			pr_warn("[selinux]: target type '%s' not found\n",
				tname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (cname && *cname) {
		cls = symtab_search(&pdb->symtab[SYM_CLASSES], cname);
		if (!cls) {
			pr_warn("[selinux]: class '%s' not found\n", cname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (pname && *pname) {
		if (!cls) {
			pr_warn("[selinux]: perm specified without class\n");
			ret = -EINVAL;
			goto out;
		}
		perm = symtab_search(&cls->permissions, pname);
		if (!perm && cls->comdatum)
			perm =
			    symtab_search(&cls->comdatum->permissions, pname);
		if (!perm) {
			pr_warn
			    ("[selinux]: perm '%s' not found in class '%s'\n",
			     pname, cname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (!src || !tgt || !cls) {
		pr_warn
		    ("[selinux]: wildcard not supported in kernel add_rule, specify all fields\n");
		ret = -EINVAL;
		goto out;
	}

	key.source_type = src->value;
	key.target_type = tgt->value;
	key.target_class = cls->value;
	key.specified = effect;

	node = avtab_search_node(&pdb->te_avtab, &key);
	if (!node) {
		memset(&datum, 0, sizeof(datum));
		datum.u.data = (effect == AVTAB_AUDITDENY) ? ~0U : 0U;

		node = avtab_insert_nonunique(&pdb->te_avtab, &key, &datum);
		if (!node) {
			pr_err("[selinux]: avtab_insert_nonunique failed\n");
			ret = -ENOMEM;
			goto out;
		}
	}

	if (invert) {
		if (perm)
			node->datum.u.data &= ~(1U << (perm->value - 1));
		else
			node->datum.u.data = 0U;
	} else {
		if (perm)
			node->datum.u.data |= 1U << (perm->value - 1);
		else
			node->datum.u.data = ~0U;
	}

out:
	mutex_unlock(&selinux_state.policy_mutex);

	if (ret == 0) {
		avc_reset();
	}
	return ret;
}

static void sepolicy_add_rule_raw(struct policydb *pdb,
				  struct type_datum *src,
				  struct type_datum *tgt,
				  struct class_datum *cls,
				  int effect, bool invert)
{
	struct hashtab_node *node;

	if (src == NULL) {
		int i;
		hashtab_for_each(pdb->p_types.table, node) {
			sepolicy_add_rule_raw(pdb,
					      (struct type_datum *)node->datum,
					      tgt, cls, effect, invert);
		}
	} else if (tgt == NULL) {
		hashtab_for_each(pdb->p_types.table, node) {
			sepolicy_add_rule_raw(pdb, src,
					      (struct type_datum *)node->datum,
					      cls, effect, invert);
		}
	} else if (cls == NULL) {
		hashtab_for_each(pdb->p_classes.table, node) {
			sepolicy_add_rule_raw(pdb, src, tgt,
					      (struct class_datum *)node->datum,
					      effect, invert);
		}
	} else {
		struct avtab_key key;
		struct avtab_node *av_node;
		struct avtab_datum datum;

		key.source_type = src->value;
		key.target_type = tgt->value;
		key.target_class = cls->value;
		key.specified = effect;

		av_node = avtab_search_node(&pdb->te_avtab, &key);
		if (!av_node) {
			memset(&datum, 0, sizeof(datum));
			datum.u.data = 0U;
			av_node =
			    avtab_insert_nonunique(&pdb->te_avtab, &key,
						   &datum);
		}

		if (av_node) {
			if (invert) {
				av_node->datum.u.data = 0U;
			} else {
				av_node->datum.u.data = ~0U;
			}
		}
	}
}

int sepolicy_allow_all_types(const char *sname, const char *cname)
{
	struct policydb *pdb;
	struct type_datum *src = NULL;
	struct class_datum *cls = NULL;
	int ret = 0;

	mutex_lock(&selinux_state.policy_mutex);

	pdb = fmac_get_pdb();
	if (!pdb) {
		ret = -ENOENT;
		goto out;
	}

	if (sname) {
		src = symtab_search(&pdb->symtab[SYM_TYPES], sname);
		if (!src) {
			pr_warn("[selinux]: source type '%s' not found\n",
				sname);
			ret = -ENOENT;
			goto out;
		}
	}

	if (cname) {
		cls = symtab_search(&pdb->symtab[SYM_CLASSES], cname);
		if (!cls) {
			pr_warn("[selinux]: class '%s' not found\n", cname);
			ret = -ENOENT;
			goto out;
		}
	}

	sepolicy_add_rule_raw(pdb, src, NULL, cls, AVTAB_ALLOWED, false);

	sepolicy_add_rule_raw(pdb, src, NULL, cls, AVTAB_AUDITDENY, true);

	pr_info
	    ("[selinux]: granted '%s' all perms to all types over class '%s'\n",
	     sname, cname);

out:
	mutex_unlock(&selinux_state.policy_mutex);

	if (ret == 0) {
		avc_reset();
	}
	return ret;
}

int sepolicy_allow_any_any(const char *sname)
{
	struct policydb *pdb;
	struct type_datum *src = NULL;
	int ret = 0;

	mutex_lock(&selinux_state.policy_mutex);

	pdb = fmac_get_pdb();
	if (!pdb) {
		ret = -ENOENT;
		goto out;
	}

	if (sname) {
		src = symtab_search(&pdb->symtab[SYM_TYPES], sname);
		if (!src) {
			pr_warn("[selinux]: source type '%s' not found\n",
				sname);
			ret = -ENOENT;
			goto out;
		}
	}

	sepolicy_add_rule_raw(pdb, src, NULL, NULL, AVTAB_ALLOWED, false);

	sepolicy_add_rule_raw(pdb, src, NULL, NULL, AVTAB_AUDITDENY, true);

	pr_info("[selinux]: '%s' has been elevated to any-any allow.\n",
		sname ? sname : "ALL DOMAINS");

out:
	mutex_unlock(&selinux_state.policy_mutex);

	if (ret == 0) {
		avc_reset();
	}
	return ret;
}
