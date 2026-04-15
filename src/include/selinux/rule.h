#ifndef RULE_H
int sepolicy_add_rule(const char *sname, const char *tname,
                            const char *cname, const char *pname,
                            int effect, bool invert);
#endif