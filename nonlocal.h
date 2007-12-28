#ifndef NONLOCAL_H
#define NONLOCAL_H
enum nss_status check_nonlocal_uid(const char *user, uid_t uid, int *errnop);
enum nss_status check_nonlocal_gid(const char *user, gid_t gid, int *errnop);
#endif /* NON_LOCAL_H */
