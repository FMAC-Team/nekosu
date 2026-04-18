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
#include "ss/constraint.h"

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

static void sepolicy_add_rule_raw(struct policydb *pdb,
				  struct type_datum *src,
				  struct type_datum *tgt,
				  struct class_datum *cls,
				  int perm_value, int effect, bool invert)
{
	struct hashtab_node *node;

	if (src == NULL) {
		hashtab_for_each(pdb->p_types.table, node) {
			sepolicy_add_rule_raw(pdb,
					      (struct type_datum *)node->datum,
					      tgt, cls, perm_value,
					      effect, invert);
		}
	} else if (tgt == NULL) {
		hashtab_for_each(pdb->p_types.table, node) {
			sepolicy_add_rule_raw(pdb, src,
					      (struct type_datum *)node->datum,
					      cls, perm_value, effect, invert);
		}
	} else if (cls == NULL) {
		hashtab_for_each(pdb->p_classes.table, node) {
			sepolicy_add_rule_raw(pdb, src, tgt,
					      (struct class_datum *)node->datum,
					      perm_value, effect, invert);
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
			datum.u.data = (effect == AVTAB_AUDITDENY) ? ~0U : 0U;
			av_node = avtab_insert_nonunique(&pdb->te_avtab, &key,
							 &datum);
		}

		if (av_node) {
			if (perm_value) {
				if (invert)
					av_node->datum.u.data &=
					    ~(1U << (perm_value - 1));
				else
					av_node->datum.u.data |=
					    1U << (perm_value - 1);
			} else {
				av_node->datum.u.data = invert ? 0U : ~0U;
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

	sepolicy_add_rule_raw(pdb, src, NULL, cls, 0, AVTAB_ALLOWED, false);

	sepolicy_add_rule_raw(pdb, src, NULL, cls, 0, AVTAB_AUDITDENY, true);

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

	sepolicy_add_rule_raw(pdb, src, NULL, NULL, 0, AVTAB_ALLOWED, false);

	sepolicy_add_rule_raw(pdb, src, NULL, NULL, 0, AVTAB_AUDITDENY, true);

	pr_info("[selinux]: '%s' has been elevated to any-any allow.\n",
		sname ? sname : "ALL DOMAINS");

out:
	mutex_unlock(&selinux_state.policy_mutex);

	if (ret == 0) {
		avc_reset();
	}
	return ret;
}

int sepolicy_add_rule(const char *sname, const char *tname,
		      const char *cname, const char *pname,
		      int effect, bool invert)
{
	struct policydb *pdb;
	struct type_datum *src = NULL, *tgt = NULL;
	struct class_datum *cls = NULL;
	struct perm_datum *perm = NULL;
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

	sepolicy_add_rule_raw(pdb, src, tgt, cls,
			      perm ? (int)perm->value : 0, effect, invert);

out:
	mutex_unlock(&selinux_state.policy_mutex);

	if (ret == 0)
		avc_reset();
	return ret;
}

static void sepolicy_add_typeattribute_raw(struct policydb *pdb,
					   struct type_datum *type_dat,
					   struct type_datum *attr_dat)
{
	struct hashtab_node *node;
	struct constraint_node *n;
	struct constraint_expr *e;

	struct ebitmap *sattr = &pdb->type_attr_map_array[type_dat->value - 1];
	ebitmap_set_bit(sattr, attr_dat->value - 1, 1);
	hashtab_for_each(pdb->p_classes.table, node) {
		struct class_datum *cls = (struct class_datum *)(node->datum);
		for (n = cls->constraints; n; n = n->next) {
			for (e = n->expr; e; e = e->next) {
				if (e->expr_type == CEXPR_NAMES && e->type_names
				    && ebitmap_get_bit(&e->type_names->types,
						       attr_dat->value - 1)) {
					ebitmap_set_bit(&e->names,
							type_dat->value - 1, 1);
				}
			}
		}
	}
}

int sepolicy_add_typeattribute(const char *type_name, const char *attr_name)
{
	struct policydb *pdb;
	struct type_datum *type_dat = NULL;
	struct type_datum *attr_dat = NULL;
	int ret = 0;

	if (!type_name || !attr_name)
		return -EINVAL;

	mutex_lock(&selinux_state.policy_mutex);

	pdb = fmac_get_pdb();
	if (!pdb) {
		ret = -ENOENT;
		goto out;
	}

	type_dat = symtab_search(&pdb->symtab[SYM_TYPES], type_name);
	if (!type_dat) {
		pr_warn("[selinux]: type '%s' not found\n", type_name);
		ret = -ENOENT;
		goto out;
	}

	attr_dat = symtab_search(&pdb->symtab[SYM_TYPES], attr_name);
	if (!attr_dat) {
		pr_warn("[selinux]: attribute '%s' not found\n", attr_name);
		ret = -ENOENT;
		goto out;
	}

	if (type_dat->attribute) {
		pr_warn("[selinux]: '%s' is an attribute, not a type\n",
			type_name);
		ret = -EINVAL;
		goto out;
	}
	if (!attr_dat->attribute) {
		pr_warn("[selinux]: '%s' is a type, not an attribute\n",
			attr_name);
		ret = -EINVAL;
		goto out;
	}

	sepolicy_add_typeattribute_raw(pdb, type_dat, attr_dat);

	pr_info("[selinux]: added attribute '%s' to type '%s'\n", attr_name,
		type_name);

out:
	mutex_unlock(&selinux_state.policy_mutex);

	if (ret == 0) {
		avc_reset();
	}
	return ret;
}

static void xperms_set_range(u32 *perms, u16 low, u16 high, bool invert)
{
	u16 i;
	if (low == 0 && high == 255 && !invert) {
		memset(perms, 0xff, 8 * sizeof(u32));	// 256 bits
		return;
	}
	for (i = low; i <= high; i++) {
		if (invert)
			perms[i / 32] &= ~(1U << (i % 32));
		else
			perms[i / 32] |= (1U << (i % 32));
	}
}

static void sepolicy_add_xperm_raw(struct policydb *db, struct type_datum *src,
                                   struct type_datum *tgt, struct class_datum *cls,
                                   u16 low, u16 high, int effect, bool invert)
{
    struct hashtab_node *node;
    struct avtab_key key;
    struct avtab_node *av_node;
    struct avtab_extended_perms *x;
    struct avtab_extended_perms *xp;
    struct avtab_datum datum;
    u8 d_low, d_high;

    if (!src) {
        hashtab_for_each(db->p_types.table, node)
            sepolicy_add_xperm_raw(db, (struct type_datum *)node->datum,
                                   tgt, cls, low, high, effect, invert);
        return;
    }
    if (!tgt) {
        hashtab_for_each(db->p_types.table, node)
            sepolicy_add_xperm_raw(db, src, (struct type_datum *)node->datum,
                                   cls, low, high, effect, invert);
        return;
    }
    if (!cls) {
        hashtab_for_each(db->p_classes.table, node)
            sepolicy_add_xperm_raw(db, src, tgt,
                                   (struct class_datum *)node->datum,
                                   low, high, effect, invert);
        return;
    }

    d_low  = (u8)(low  >> 8);
    d_high = (u8)(high >> 8);

    key.source_type  = src->value;
    key.target_type  = tgt->value;
    key.target_class = cls->value;
    key.specified    = effect;

    av_node = avtab_search_node(&db->te_avtab, &key);
    if (!av_node) {
        xp = kzalloc(sizeof(struct avtab_extended_perms), GFP_KERNEL);
        if (!xp)
            return;

        if (d_low != d_high) {
            xp->specified = AVTAB_XPERMS_IOCTLDRIVER;
            xp->driver    = 0;
        } else {
            xp->specified = AVTAB_XPERMS_IOCTLFUNCTION;
            xp->driver    = d_low;
        }

        memset(&datum, 0, sizeof(datum));
        datum.u.xperms = xp;

        av_node = avtab_insert_nonunique(&db->te_avtab, &key, &datum);
        if (!av_node) {
            kfree(xp);
            return;
        }
    }

    x = av_node->datum.u.xperms;
    if (!x)
        return;

    if (x->specified == AVTAB_XPERMS_IOCTLDRIVER) {
        xperms_set_range(x->perms.p, d_low, d_high, invert);
    } else if (x->driver == d_low) {
        xperms_set_range(x->perms.p,
                         (u8)(low  & 0xFF),
                         (u8)(high & 0xFF), invert);
    }
}

int sepolicy_add_xperm(const char *s, const char *t, const char *c,
		       const char *range, int effect, bool invert)
{
	struct policydb *pdb;
	struct type_datum *src = NULL, *tgt = NULL;
	struct class_datum *cls = NULL;
	u16 low = 0, high = 0;
	int ret = 0;

	if (!range || !*range) {
		low = 0;
		high = 0xFFFF;
	} else if (strchr(range, '-')) {
		if (sscanf(range, "0x%hx-0x%hx", &low, &high) != 2 &&
		    sscanf(range, "%hx-%hx", &low, &high) != 2)
			return -EINVAL;
	} else {
		sscanf(range, "%hx", &low);
		high = low;
	}

	mutex_lock(&selinux_state.policy_mutex);

	pdb = fmac_get_pdb();
	if (!pdb) {
		ret = -ENOENT;
		goto out;
	}
	if (s && *s) {
		src = symtab_search(&pdb->symtab[SYM_TYPES], s);
		if (!src) {
			ret = -ENOENT;
			goto out;
		}
	}
	if (t && *t) {
		tgt = symtab_search(&pdb->symtab[SYM_TYPES], t);
		if (!tgt) {
			ret = -ENOENT;
			goto out;
		}
	}
	if (c && *c) {
		cls = symtab_search(&pdb->symtab[SYM_CLASSES], c);
		if (!cls) {
			ret = -ENOENT;
			goto out;
		}
	}
	sepolicy_add_xperm_raw(pdb, src, tgt, cls, low, high, effect, invert);

out:
	mutex_unlock(&selinux_state.policy_mutex);
	if (ret == 0)
		avc_reset();
	return ret;
}
