#ifndef RULE_H
int sepolicy_add_rule(const char *sname, const char *tname,
                            const char *cname, const char *pname,
                            int effect, bool invert);
int sepolicy_allow_any_any(const char *sname);
int sepolicy_allow_all_types(const char *sname, const char *cname);
int sepolicy_add_typeattribute(const char *type_name, const char *attr_name);
#endif