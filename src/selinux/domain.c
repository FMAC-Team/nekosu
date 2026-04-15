#include <linux/slab.h>
#include <linux/string.h>
#include <linux/rwlock.h>
#include "ss/policydb.h"
#include "ss/services.h"
#include "ss/ebitmap.h"

static int add_type_to_role(struct policydb *p, const char *role_name, uint32_t type_value)
{
    struct role_datum *role;

    role = hashtab_search(p->p_roles.table, role_name);
    if (!role) {
        pr_err("[selinux] Role %s not found\n", role_name);
        return -EINVAL;
    }

    return ebitmap_set_bit(&role->types, type_value - 1, 1);
}

static int policydb_reindex_types(struct policydb *p, uint32_t new_nprim, char *name_copy)
{
    char **new_val_to_name;
    struct ebitmap *new_attr_map;

    new_val_to_name = krealloc(p->type_val_to_name, 
                               sizeof(char *) * new_nprim, GFP_KERNEL);
    if (!new_val_to_name)
        return -ENOMEM;
    p->type_val_to_name = new_val_to_name;
    p->type_val_to_name[new_nprim - 1] = name_copy;

    new_attr_map = krealloc(p->type_attr_map_array, 
                            sizeof(struct ebitmap) * new_nprim, GFP_KERNEL);
    if (!new_attr_map)
        return -ENOMEM;
    p->type_attr_map_array = new_attr_map;
    
    ebitmap_init(&p->type_attr_map_array[new_nprim - 1]);

    return 0;
}

int sepolicy_add_domain(const char *name)
{
    struct policydb *p = &selinux_state.policydb;
    struct type_datum *type_dat;
    char *name_copy;
    int rc;

    if (hashtab_search(p->p_types.table, name))
        return 0;

    type_dat = kzalloc(sizeof(*type_dat), GFP_KERNEL);
    if (!type_dat)
        return -ENOMEM;

    name_copy = kstrdup(name, GFP_KERNEL);
    if (!name_copy) {
        kfree(type_dat);
        return -ENOMEM;
    }

    type_dat->primary = 1;
    type_dat->value = p->p_types.nprim + 1;

    rc = policydb_reindex_types(p, type_dat->value, name_copy);
    if (rc) {
        kfree(name_copy);
        kfree(type_dat);
        return rc;
    }

    rc = hashtab_insert(p->p_types.table, name_copy, type_dat);
    if (rc) {
        return rc;
    }
    p->p_types.nprim++;

    rc = add_type_to_attr(p, name, "domain");
    if (rc) pr_warn("[selinux] Failed to add domain attr\n");

    rc = add_type_to_role(p, "system_r", type_dat->value);
    if (rc) pr_warn("[selinux] Failed to link to system_r\n");

    pr_info("[selinux] Domain '%s' added successfully with ID %d\n", name, type_dat->value);
    return 0;
}