/*
 * Copyright (C) 2014, 2015, 2016 Cumulus Networks, Inc.
 * Copyright (C) 2017 Chenchen Qi
 * All rights reserved.
 * Author: Dave Olson <olson@cumulusnetworks.com>
 *         Chenchen Qi <chenchen.qcc@alibaba-inc.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 */

/*
 * This plugin implements getpwnam_r for NSS over TACACS+.
 */

#include <string.h>
#include <syslog.h>
#include <stdbool.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <netdb.h>
#include <nss.h>
#include <limits.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#include <libtac/libtac.h>

#define MIN_TACACS_USER_PRIV (1)
#define MAX_TACACS_USER_PRIV (15)

#define GET_ENV_VARIABLE_OK                 0
#define GET_ENV_VARIABLE_NOT_FOUND          1
#define GET_ENV_VARIABLE_INCORRECT_FORMAT   2
#define GET_ENV_VARIABLE_NOT_ENOUGH_BUFFER  3
#define GET_REMOTE_ADDRESS_OK               0
#define GET_REMOTE_ADDRESS_FAILED           1

// When parallel connection to multiple TACACS server, after first
// server successfully connected, other server need have a slightly
// delay to avoid authentication with multiple server factor is 4
// because there will be 4 packets send/receve with server
#define TACACS_SERVER_DELAY_FACTOR          4

static const char *nssname = "nss_tacplus"; /* for syslogs */
static const char *config_file = "/etc/tacplus_nss.conf";
static const char *user_conf = "/etc/tacplus_user";
static const char *user_conf_tmp = "/tmp/tacplus_user_tmp";

/*
 * pwbuf is used to reduce number of arguments passed around; the strings in
 * the passwd struct need to point into this buffer.
 */
struct pwbuf {
    char *name;
    char *buf;
    struct passwd *pw;
    int *errnop;
    size_t buflen;
};

typedef struct {
    struct addrinfo *addr;
    char *key;
    int timeout;
}tacplus_server_t;

typedef struct {
    char *info;
    int gid;
    char *secondary_grp;
    char *shell;
}useradd_info_t;

/* set from configuration file parsing */
static tacplus_server_t tac_srv[TAC_PLUS_MAXSERVERS];
static int tac_srv_no;
static useradd_info_t useradd_grp_list[MAX_TACACS_USER_PRIV + 1];
static struct addrinfo *source_addr;

static char *tac_service = "shell";
static char *tac_protocol = "ssh";
static char vrfname[64];
static bool debug = false;
static bool many_to_one = false;

/* variables for parallel TACACS connection */
static bool tacacs_auth_success = false;
static bool tacacs_auth_finish = false;
static int finish_server_count = 0;
static unsigned long server_priv_level = 0;
static uint64_t min_tac_srv_latency_us;

#define max(a,b) \
    ({ __typeof__ (a) _a = (a); \
    __typeof__ (b) _b = (b); \
    _a > _b ? _a : _b; })

typedef struct
{
    const char *name;
    int srvr;
    char *remote_addr;
    const char* current_tty;
} tacacs_thread_args_t;

static int parse_tac_server(char *srv_buf)
{
    char *token;
    char delim[] = " ,\t\n\r\f";

    token = strsep(&srv_buf, delim);
    while(token) {
        if('\0' != token[0]) {
            if(!strncmp(token, "server=", 7)) {
                struct addrinfo hints, *server;
                int rv;
                char *srv, *port;

                memset(&hints, 0, sizeof hints);
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;

                srv = token + 7;
                port = strrchr(srv, ':');
                if(port) {
                    *port = '\0';
                    port++;
                }

                if((rv = getaddrinfo(srv, (port == NULL) ? "49" : port, &hints,
                    &server)) == 0) {
                    if(server) {
                        if(tac_srv[tac_srv_no].addr)
                            freeaddrinfo(tac_srv[tac_srv_no].addr);
                        if(tac_srv[tac_srv_no].key)
                            free(tac_srv[tac_srv_no].key);
                        memset(tac_srv + tac_srv_no, 0, sizeof(tacplus_server_t));

                        tac_srv[tac_srv_no].addr = server;
                    }
                    else {
                        syslog(LOG_ERR, "%s: server NULL", nssname);
                    }
                }
                else {
                    syslog(LOG_ERR, "%s: invalid server: %s (getaddrinfo: %s)",
                        nssname, srv, gai_strerror(rv));
                    return -1;
                }
            }
            else if(!strncmp(token, "vrf=", 4)){
                strncpy(vrfname, token + 4, sizeof(vrfname) - 1);
                vrfname[sizeof(vrfname) - 1] = '\0';
            }
            else if(!strncmp(token, "secret=", 7)) {
                if(tac_srv[tac_srv_no].key)
                    free(tac_srv[tac_srv_no].key);
                tac_srv[tac_srv_no].key = strdup(token + 7);
            }
            else if(!strncmp(token, "timeout=", 8)) {
                tac_srv[tac_srv_no].timeout = (int)strtoul(token + 8, NULL, 0);
                if(tac_srv[tac_srv_no].timeout < 0)
                    tac_srv[tac_srv_no].timeout = 0;
                /* Limit timeout to make sure upper application not wait
                 * for a long time*/
                if(tac_srv[tac_srv_no].timeout > 5)
                    tac_srv[tac_srv_no].timeout = 5;
            }
        }
        token = strsep(&srv_buf, delim);
    }

    return 0;
}

static int parse_user_priv(char *buf)
{
    char *token;
    char delim[] = ";\n\r";
    int priv = 0;
    int gid = 0;
    char *info = NULL;
    char *group = NULL;
    char *shell = NULL;

    token = strsep(&buf, delim);
    while(token) {
        if('\0' != token[0]) {
            if(!strncmp(token, "user_priv=", 10)) {
                priv = (int)strtoul(token + 10, NULL, 0);
                if(priv > MAX_TACACS_USER_PRIV || priv < MIN_TACACS_USER_PRIV)
                {
                    priv = 0;
                    syslog(LOG_WARNING, "%s: user_priv %d out of range",
                        nssname, priv);
                }
            }
            else if(!strncmp(token, "pw_info=", 8)) {
                if(!info)
                    info = strdup(token + 8);
            }
            else if(!strncmp(token, "gid=", 4)) {
                gid = (int)strtoul(token + 4, NULL, 0);
            }
            else if(!strncmp(token, "group=", 6)) {
                if(!group)
                    group = strdup(token + 6);
            }
            else if(!strncmp(token, "shell=", 6)) {
                if(!shell)
                    shell = strdup(token + 6);
            }
        }
        token = strsep(&buf, delim);
    }

    if(priv && gid && info && group && shell) {
        useradd_info_t *user = &useradd_grp_list[priv];
        if(user->info)
            free(user->info);
        if(user->secondary_grp)
            free(user->secondary_grp);
        if(user->shell)
            free(user->shell);

        user->gid = gid;
        user->info = info;
        user->secondary_grp = group;
        user->shell = shell;
        syslog(LOG_DEBUG, "%s: user_priv=%d info=%s gid=%d group=%s shell=%s",
                nssname, priv, info, gid, group, shell);
    }
    else {
        if(info)
            free(info);
        if(group)
            free(group);
        if(shell)
            free(shell);
    }

    return 0;
}

static void init_useradd_info()
{
    useradd_info_t *user;

    user = &useradd_grp_list[MIN_TACACS_USER_PRIV];
    user->gid = 100;
    user->info = strdup("remote_user");
    user->secondary_grp = strdup("users");
    user->shell = strdup("/bin/bash");

    user = &useradd_grp_list[MAX_TACACS_USER_PRIV];
    user->gid = 1000;
    user->info = strdup("remote_user_su");
    user->secondary_grp = strdup("sudo,docker");
    user->shell = strdup("/bin/bash");
}

static int parse_config(const char *file)
{
    FILE *fp;
    char buf[512] = {0};

    init_useradd_info();
    fp = fopen(file, "r");
    if(!fp) {
        syslog(LOG_ERR, "%s: %s fopen failed", nssname, file);
        return NSS_STATUS_UNAVAIL;
    }

    if(source_addr) {
        freeaddrinfo(source_addr);
        source_addr = NULL;
    }
    debug = false;
    tac_srv_no = 0;
    while(fgets(buf, sizeof buf, fp)) {
        if('#' == *buf || isspace(*buf))
            continue;

        if(!strncmp(buf, "debug=on", 8)) {
            debug = true;
        }
        else if(!strncmp(buf, "many_to_one=y", 13)) {
            many_to_one = true;
        }
        else if(!strncmp(buf, "user_priv=", 10)) {
            parse_user_priv(buf);
        }
        else if(!strncmp(buf, "src_ip=", 7)) {
            struct addrinfo hints;
            char *ip = buf + 7, *new_line;

            // Remove the new line character as getaddrinfo is not working for IPv6 address with '\n'.
            if ((new_line = strchr(buf, '\n')) != NULL) {
                *new_line = '\0';
            }
            memset(&hints, 0, sizeof hints);
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            if(0 != getaddrinfo(ip, NULL, &hints, &source_addr))
                syslog(LOG_ERR, "%s: error setting the source ip information",
                    nssname);
        }
        else if(!strncmp(buf, "server=", 7)) {
            if(TAC_PLUS_MAXSERVERS <= tac_srv_no) {
                syslog(LOG_ERR, "%s: tac server num is more than %d",
                    nssname, TAC_PLUS_MAXSERVERS);
            }
            else if(0 == parse_tac_server(buf))
                ++tac_srv_no;
        }
    }
    fclose(fp);

    if(debug) {
        int n;
        useradd_info_t *user;

        for(n = 0; n < tac_srv_no; n++) {
            syslog(LOG_DEBUG, "%s: server[%d] { addr=%s, key=%c*****, timeout=%d }",
                        nssname, n, tac_ntop(tac_srv[n].addr->ai_addr),
                        tac_srv[n].key[0], tac_srv[n].timeout);
        }
        syslog(LOG_DEBUG, "%s: src_ip=%s", nssname, NULL == source_addr
                    ? "NULL" : tac_ntop(source_addr->ai_addr));
        syslog(LOG_DEBUG, "%s: many_to_one %s", nssname, 1 == many_to_one
                    ? "enable" : "disable");
        for(n = MIN_TACACS_USER_PRIV; n <= MAX_TACACS_USER_PRIV; n++) {
            user = &useradd_grp_list[n];
            if(user) {
                syslog(LOG_DEBUG, "%s: user_priv[%d] { gid=%d, info=%s, group=%s, shell=%s }",
                            nssname, n, user->gid, NULL == user->info ? "NULL" : user->info,
                            NULL == user->secondary_grp ? "NULL" : user->secondary_grp,
                            NULL == user->shell ? "NULL" : user->shell);
            }
        }
    }

    return 0;
}

/*
 * copy a passwd structure and it's strings, using the provided buffer
 * for the strings.
 * if usename is non-NULL, use that, rather than pw_name in srcpw, so we can
 * preserve the original requested name (this is part of the tacacs remapping).
 * For strings, if pointer is null, use an empty string.
 * Returns 0 if everything fit, otherwise 1.
 */
static int
pwcopy(char *buf, size_t len, struct passwd *srcpw, struct passwd *destpw,
       const char *usename)
{
    size_t needlen;
    int cnt;

    if(!usename)
        usename = srcpw->pw_name;

    needlen = (usename ? strlen(usename) + 1 : 1) +
        (srcpw->pw_dir ? strlen(srcpw->pw_dir) + 1 : 1) +
        (srcpw->pw_gecos ? strlen(srcpw->pw_gecos) + 1 : 1) +
        (srcpw->pw_shell ? strlen(srcpw->pw_shell) + 1 : 1) +
        (srcpw->pw_passwd ? strlen(srcpw->pw_passwd) + 1 : 1);
    if(needlen > len) {
        if(debug)
            syslog(LOG_DEBUG, "%s provided password buffer too small (%ld<%ld)",
                nssname, (long)len, (long)needlen);
        return 1;
    }

    destpw->pw_uid = srcpw->pw_uid;
    destpw->pw_gid = srcpw->pw_gid;

    cnt = snprintf(buf, len, "%s", usename ? usename : "");
    destpw->pw_name = buf;
    cnt++; /* allow for null byte also */
    buf += cnt;
    len -= cnt;
    /* If many-to-one mapping, set pw_passwd "a" for pam_account success */
    cnt = snprintf(buf, len, "%s", 0 == many_to_one ? "x" : "a");
    destpw->pw_passwd = buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s", srcpw->pw_shell ? srcpw->pw_shell : "");
    destpw->pw_shell = buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s", srcpw->pw_gecos ? srcpw->pw_gecos : "");
    destpw->pw_gecos = buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s", srcpw->pw_dir ? srcpw->pw_dir : "");
    destpw->pw_dir = buf;
    cnt++;
    buf += cnt;
    len -= cnt;

    return 0;
}

/*
 * If useradd finished, user name should be deleted in conf.
 */
static int delete_conf_line(const char *name)
{
    FILE *fp, *fp_tmp;
    char line[128];
    char del_line[128];
    int len = strlen(name);

    if(len >= 126) {
        syslog(LOG_ERR, "%s: user name %s out of range 128", nssname, name);
        return -1;
    }
    else {
        snprintf(del_line, 128, "%s\n", name);
    }

    fp = fopen(user_conf, "r");
    if(!fp) {
        syslog(LOG_ERR, "%s: %s fopen failed", nssname, user_conf);
        return NSS_STATUS_UNAVAIL;
    }
    fp_tmp = fopen(user_conf_tmp, "w");
    if(!fp_tmp) {
        syslog(LOG_ERR, "%s: %s fopen failed", nssname, user_conf_tmp);
        fclose(fp);
        return NSS_STATUS_UNAVAIL;
    }

    while(fgets(line, sizeof line, fp)) {
        if(strcmp(line, del_line)) {
            fprintf(fp_tmp, "%s", line);
        }
    }
    fclose(fp_tmp);
    fclose(fp);

    if(0 != remove(user_conf) || 0 != rename(user_conf_tmp, user_conf)) {
        syslog(LOG_ERR, "%s: %s rewrite failed", nssname, user_conf);
        return -1;
    }

    return 0;
}

int user_mod_add(const char* cmd, const char* name, char* gid, char* sec_grp, char* gecos, char* home, char* shell) {

    pid_t pid;
    int wstatus;

    pid = fork();

    if(pid > 0) {
        do {
            if (waitpid(pid, &wstatus, WUNTRACED | WCONTINUED) == -1) {
                int errsv = errno;
                char serr[256] = {0};
                strerror_r(errsv, serr, 256);
                syslog(LOG_ERR, "%s: exec of %s failed with error %d: %s", nssname, cmd, errsv, serr);
                return -1;
            }
        } while (!WIFEXITED(wstatus) && !WIFSIGNALED(wstatus));
        if WIFEXITED(wstatus)
            return WEXITSTATUS(wstatus);
        else
            return -1;
    // Child
    } else if(pid == 0) {
        execl(cmd, cmd, "-G", sec_grp, name, "-g", gid, "-c", gecos, "-d", home, "-m", "-s", shell, NULL);
        syslog(LOG_ERR, "%s: exec of %s failed with errno=%d", nssname, cmd, errno);
        exit(EXIT_FAILURE);
    // Error
    } else {
        syslog(LOG_ERR, "%s: error forking the child\n", nssname);
        return -1;
    }
}

/*
 * If not found in local, look up in tacacs user conf. If user name is not in
 * conf, it will be written in conf and created by command 'useradd'. When
 * useradd command use getpwnam(), it will return when username found in conf.
 */
static int create_or_modify_local_user(const char *name, int level, bool existing_user)
{
    FILE *fp;
    useradd_info_t *user;
    char buf[512];
    int len = 512;
    int lvl, cnt;
    bool found = false;
    const char* command = existing_user ? "/usr/sbin/usermod": "/usr/sbin/useradd";

    if(strlen(name) > 32) {
        syslog(LOG_ERR, "%s: Username too long", nssname);
        return -1;
    }

    fp = fopen(user_conf, "ab+");
    if(!fp) {
        syslog(LOG_ERR, "%s: %s fopen failed", nssname, user_conf);
        return -1;
    }

    while(fgets(buf, sizeof buf, fp)) {
        if('#' == *buf || isspace(*buf))
            continue;
        // Delete line break
        cnt = strlen(buf);
        buf[cnt - 1] = '\0';
        if(!strcmp(buf, name)) {
            found = true;
            break;
        }
    }

    /*
     * If user is found in user_conf, it means that getpwnam is called by
     * useradd in this NSS module.
     */
    if(found) {
        if(debug)
            syslog(LOG_DEBUG, "%s: %s found in %s", nssname, name, user_conf);
        fclose(fp);
        return 1;
    }

    snprintf(buf, len, "%s\n", name);
    if(EOF == fputs(buf, fp)) {
        syslog(LOG_ERR, "%s: %s write local user failed", nssname, name);
        fclose(fp);
        return -1;
    }
    fclose(fp);

    lvl = level;
    while(lvl >= MIN_TACACS_USER_PRIV) {
        user = &useradd_grp_list[lvl];
        if(user->info && user->secondary_grp && user->shell) {
            char sgid[10] = {0};
            char home[64] = {0};
            snprintf(sgid, 10, "%d", user->gid);
            snprintf(home, 63, "/home/%s", name);
            if(0 != user_mod_add(command, name, sgid, user->secondary_grp, user->info, home, user->shell)) {
                syslog(LOG_ERR, "%s: %s %s failed", nssname, command, name);
                delete_conf_line(name);
                return -1;
            }
            if(debug)
                syslog(LOG_DEBUG, "%s: %s %s success", nssname, command, name);

            delete_conf_line(name);
            return 0;
        }
        lvl--;
    }

    return -1;
}

/*
 * Lookup user in /etc/passwd, and fill up passwd info if found.
 */
static int lookup_pw_local(const char* username, struct pwbuf *pb, bool *found)
{
    FILE *fp;
    struct passwd *pw = NULL;
    int ret = 0;

    if(!username) {
        syslog(LOG_ERR, "%s: username invalid in check passwd", nssname);
        return -1;
    }

    fp = fopen("/etc/passwd", "r");
    if(!fp) {
        syslog(LOG_ERR, "%s: /etc/passwd fopen failed", nssname);
        return -1;
    }

    while(0 != (pw = fgetpwent(fp))) {
        if(!strcmp(pw->pw_name, username)) {
            *found = true;
            ret = pwcopy(pb->buf, pb->buflen, pw, pb->pw, username);
            if(ret)
                *pb->errnop = ERANGE;
            break;
        }
    }
    fclose(fp);
    return ret;
}

/*
 * Return true, if user has entry in /etc/passwd and his gecos
 * does not match with expected gecos for any tacacs user of any
 * privilege level.
 */
static bool is_non_tacacs_user(const char *name)
{
    char buf[1024];
    struct passwd pw;
    int err = 0;
    struct pwbuf pwbuf;
    bool found = false;
    bool ret = false;

    pwbuf.buf = buf;
    pwbuf.pw = &pw;
    pwbuf.errnop = &err;
    pwbuf.buflen = sizeof(buf);

    lookup_pw_local(name, &pwbuf, &found);

    if (found && (err == 0)) {
        int i = MIN_TACACS_USER_PRIV;
        const useradd_info_t *pinfo = &useradd_grp_list[i];

        for(; (i <= MAX_TACACS_USER_PRIV); ++i, ++pinfo) {
            if ((pinfo->info != NULL) &&
                (strcmp(pinfo->info, pwbuf.pw->pw_gecos) == 0)) {
                break;
            }
        }
        if (i > MAX_TACACS_USER_PRIV) {
            /* gecos did not match with gecos of any tacacs user info */
            ret = true;
        }
    }
    return ret;
}

/*
 * Lookup local user passwd info for TACACS+ user. If not found, local user will
 * be created by user mapping strategy.
 */
static int lookup_user_pw(struct pwbuf *pb, int level)
{
    char *username = NULL;
    char buf[128];
    int len = 128;
    bool found = false;
    int ret = 0;

    if(level < MIN_TACACS_USER_PRIV || level > MAX_TACACS_USER_PRIV) {
        syslog(LOG_ERR, "%s: TACACS+ user %s privilege %d invalid", nssname, pb->name, level);
        return -1;
    }

    /*
     * If many-to-one user mapping disable, create local user for each TACACS+ user
     * The username of local user and TACACS+ user is the same. If many-to-one enable,
     * look up the mapped local user name and passwd info.
     */
    if(0 == many_to_one) {
        username = pb->name;
    }
    else {
        int lvl = level;
        useradd_info_t *user;

        while(lvl >= MIN_TACACS_USER_PRIV) {
            user = &useradd_grp_list[lvl];
            if(user->info && user->secondary_grp && user->shell) {
                snprintf(buf, len, "%s", user->info);
                username = buf;
                if(debug)
                    syslog(LOG_DEBUG, "%s: %s mapping local user %s", nssname,
                        pb->name, username);
                break;
            }
            lvl--;
        }
    }

    ret = lookup_pw_local(username, pb, &found);
    if(debug)
        syslog(LOG_DEBUG, "%s: %s passwd %s found in local", nssname, username,
            found ? "is" : "isn't");
    if(0 != ret)
        return ret;

    if(0 == getuid()) {
        if(0 != create_or_modify_local_user(username, level, found))
            return -1;
    } else {
        if(debug)
            syslog(LOG_DEBUG, "%d does not privilege to create or modify user %s", getuid(), username);
    }

    ret = lookup_pw_local(username, pb, &found);
    if(0 == ret && !found) {
        syslog(LOG_ERR, "%s: %s not found in local after useradd",  nssname, pb->name);
        ret = -1;
    }

    return ret;
}

/*
 * we got the user back.  Go through the attributes,
 * find their privilege level.
 * Returns privilege level.
 */
static unsigned long
got_tacacs_priv_level(struct tac_attrib *attr, const char* name)
{
    unsigned long priv_level = 0;

    while(attr != NULL)  {
        /* we are looking for the privilege attribute, can be in several forms,
         * typically priv-lvl= or priv_lvl= */
        if(strncasecmp(attr->attr, "priv", 4) == 0) {
            char *ok, *val;

            for(val=attr->attr; *val && *val != '*' && *val != '='; val++)
                ;
            if(!*val)
                continue;
            val++;

            priv_level = strtoul(val, &ok, 0);

            /* if this fails, we leave priv_level at 0, which is
             * least privileged, so that's OK, but at least report it
             */
            if(debug)
                syslog(LOG_DEBUG, "%s: privilege for %s, (%lu)",
                    nssname, name, priv_level);
        }
        attr = attr->next;
    }

    return priv_level;
}

/*
 * we got the privilege level, map to the local user, fill in the data, etc.
 * Returns 0 on success, 1 on errors.
 */
static int
got_tacacs_user(struct pwbuf *pb, unsigned long priv_level)
{
    int ret = lookup_user_pw(pb, priv_level);
    if(!ret && debug)
        syslog(LOG_DEBUG, "%s: pw_name=%s, pw_passwd=%s, pw_shell=%s, dir=%s",
                nssname, pb->pw->pw_name, pb->pw->pw_passwd, pb->pw->pw_shell,
                pb->pw->pw_dir);

    return ret;
}

/*
 * Attempt to connect to the requested tacacs server.
 * Returns fd for connection, or -1 on failure
 */

static int
connect_tacacs(struct tac_attrib **attr, int srvr)
{
    int fd;

    if(!*tac_service) /* reported at config file processing */
        return -1;

    fd = tac_connect_single(tac_srv[srvr].addr, tac_srv[srvr].key, source_addr,
                            tac_srv[srvr].timeout, vrfname[0] ? vrfname : NULL);
    if(fd >= 0) {
        *attr = NULL; /* so tac_add_attr() allocates memory */
        tac_add_attrib(attr, "service", tac_service);
        if(tac_protocol[0])
            tac_add_attrib(attr, "protocol", tac_protocol);
        /* empty cmd is required, at least for linux tac_plus */
        tac_add_attrib(attr, "cmd", "");
    }
    return fd;
}

/*
 * Get environment variable first part by name and delimiters
 */
int get_environment_variable_first_part(char* dst, socklen_t size, const char* name, const char* delimiters)
{
    memset(dst, 0, size);

    const char* variable = getenv(name);
    if (variable == NULL) {
        if (debug) {
            syslog(LOG_DEBUG, "%s: can't get environment variable %s, errno=%d", nssname, name, errno);
        }

        return GET_ENV_VARIABLE_NOT_FOUND;
    }

    char* context = NULL;
    char* first_part = strtok_r((char *)variable, delimiters, &context);
    if (first_part == NULL) {
        if (debug) {
            syslog(LOG_DEBUG, "%s: can't split %s by delimiters %s", nssname, variable, delimiters);
        }

        return GET_ENV_VARIABLE_INCORRECT_FORMAT;
    }

    int first_part_len = strlen(first_part);
    if (first_part_len >= size) {
        if (debug) {
            syslog(LOG_DEBUG, "%s: dest buffer size %d not enough for %s", nssname, size, first_part);
        }

        return GET_ENV_VARIABLE_NOT_ENOUGH_BUFFER;
    }

    strncpy(dst, first_part, size);
    if (debug) {
        syslog(LOG_DEBUG, "%s: remote address=%s", nssname, dst);
    }

    return GET_ENV_VARIABLE_OK;
}

/*
 * Get current SSH session remote address from environment variable
 */
int get_remote_address(char* dst, socklen_t size)
{
    // SSHD will create environment variable SSH_CONNECTION after user session created.
    if (get_environment_variable_first_part(dst, size, "SSH_CONNECTION", " ") == GET_ENV_VARIABLE_OK) {
        return GET_REMOTE_ADDRESS_OK;
    }

    // Before user session created, SSHD will create environment variable SSH_CLIENT_IPADDR_PORT.
    if (get_environment_variable_first_part(dst, size, "SSH_CLIENT_IPADDR_PORT", " ") == GET_ENV_VARIABLE_OK) {
        return GET_REMOTE_ADDRESS_OK;
    }

    return GET_REMOTE_ADDRESS_FAILED;
}

uint64_t get_time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000 + ts.tv_nsec;
}

/*
 * lookup the user on a TACACS server.  Returns 0 on successful lookup, else 1
 *
 * Make a new connection each time, because libtac is single threaded and
 * doesn't support multiple connects at the same time due to use of globals,
 * and doesn't have support for persistent connections.   That's fixable, but
 * not worth the effort at this point.
 * Step through all servers until success or end of list, because different
 * servers can have different databases.
 */
static void *
lookup_tacacs_user_thread(void* args)
{
    // pthread_create require thread method only have 1 void* parameter.
    const char *name = ((tacacs_thread_args_t*)args)->name;
    int srvr = ((tacacs_thread_args_t*)args)->srvr;
    char *remote_addr = ((tacacs_thread_args_t*)args)->remote_addr;
    const char* current_tty = ((tacacs_thread_args_t*)args)->current_tty;
    free(args);

    struct areply arep;
    int ret = 1;
    struct tac_attrib *attr;
    int tac_fd;

    // record tacacs server connect latency
    uint64_t latency_ns = get_time_ns();
    arep.msg = NULL;
    arep.attr = NULL;
    arep.status = TAC_PLUS_AUTHOR_STATUS_ERROR; /* if author_send fails */
    tac_fd = connect_tacacs(&attr, srvr);
    if (tac_fd < 0) {
        if(debug)
            syslog(LOG_WARNING, "%s: failed to connect TACACS+ server %s,"
                " ret=%d: %m", nssname, tac_srv[srvr].addr ?
                tac_ntop(tac_srv[srvr].addr->ai_addr) : "unknown", tac_fd);
        
        // current TACACS connection thread finish
        goto exit_tacacs_thread;
    }

    // use the min tac server connect latency to delay other TACACS server connection.
    // this will make sure in most case SONiC device only AAA with single TACACS server.
    // backup min_tac_srv_latency_us before update, delay_ns will be 0 if current server is
    // the first server finish connection, which means first finish connection server
    // no delay in following steps.
    uint64_t delay_ms = min_tac_srv_latency_us/1000;
    uint64_t server_latency_us = max(get_time_ns() - latency_ns, 1000);
    min_tac_srv_latency_us = max(min_tac_srv_latency_us, server_latency_us);

    // delay here so faster server may finish authorization
    usleep(delay_ms * TACACS_SERVER_DELAY_FACTOR);
    if (tacacs_auth_finish) {
        if(debug)
            syslog(LOG_DEBUG, "%s: TACACS connect thread %d stop because other TACACS server connection finished", nssname, srvr);

        goto exit_tacacs_thread;
    }

    ret = tac_author_send(tac_fd, name, current_tty != NULL ? (char *)current_tty : "", remote_addr, attr);
    if(ret < 0) {
        if(debug)
            syslog(LOG_WARNING, "%s: TACACS+ server %s send failed (%d) for"
                " user %s: %m", nssname, tac_srv[srvr].addr ?
                tac_ntop(tac_srv[srvr].addr->ai_addr) : "unknown",
                ret, name);
        goto exit_tacacs_thread;
    }

    if (tacacs_auth_finish) {
        if(debug)
            syslog(LOG_DEBUG, "%s: TACACS connect thread %d stop because other TACACS server connection finished", nssname, srvr);

        goto exit_tacacs_thread;
    }

    errno = 0;
    ret = tac_author_read(tac_fd, &arep);
    tac_free_attrib(&attr);
    if (ret == LIBTAC_STATUS_PROTOCOL_ERR) {
        syslog(LOG_WARNING, "%s: TACACS+ server %s read failed with"
            " protocol error (incorrect shared secret?) user %s",
            nssname, tac_ntop(tac_srv[srvr].addr->ai_addr), name);
    }
    else if (ret < 0) { /*  ret == 1 OK transaction, use arep.status */
        syslog(LOG_WARNING, "%s: TACACS+ server %s read failed (%d) for"
            " user %s: %m", nssname,
            tac_ntop(tac_srv[srvr].addr->ai_addr), ret, name);
        goto exit_tacacs_thread;
    }

    if (tacacs_auth_finish) {
        if(debug)
            syslog(LOG_DEBUG, "%s: TACACS connect thread %d stop because other TACACS server connection finished", nssname, srvr);

        goto exit_tacacs_thread;
    }

    // authorization success or failed, set tacacs_auth_finish to stop other server thread
    tacacs_auth_finish = true;

    if(arep.status == AUTHOR_STATUS_PASS_ADD ||
        arep.status == AUTHOR_STATUS_PASS_REPL) {
        server_priv_level = got_tacacs_priv_level(arep.attr, name);
        if(debug)
            syslog(LOG_DEBUG, "%s: TACACS+ server %s successful for user %s."
                " local lookup %s", nssname,
                tac_ntop(tac_srv[srvr].addr->ai_addr), name,
                ret == 0?"OK":"no match");
        tacacs_auth_success = true; /* set flag to notify other TACACS connection thread stop */
    }
    else if(debug){
        syslog(LOG_DEBUG, "%s: TACACS+ server %s successful for user %s."
            " invalid (%d)", nssname,
            tac_ntop(tac_srv[srvr].addr->ai_addr), name,
            arep.status);
    }

exit_tacacs_thread:
    if (tac_fd >= 0)
        close(tac_fd);
    if(arep.msg)
        free(arep.msg);
    if(arep.attr) /* free returned attributes */
        tac_free_attrib(&arep.attr);

    finish_server_count += 1;

    pthread_exit(NULL);
}

/*
 * lookup the user on a TACACS server.  Returns 0 on successful lookup, else 1
 *
 * Make a new connection each time, because libtac is single threaded and
 * doesn't support multiple connects at the same time due to use of globals,
 * and doesn't have support for persistent connections.   That's fixable, but
 * not worth the effort at this point.
 * Step through all servers until success or end of list, because different
 * servers can have different databases.
 */
static int
lookup_tacacs_user(struct pwbuf *pb)
{
    int ret = 1;
    int srvr;
    char remote_addr[INET6_ADDRSTRLEN];
    const char* current_tty = getenv("SSH_TTY");

    int result = get_remote_address(remote_addr, sizeof(remote_addr));
    if ((result != GET_REMOTE_ADDRESS_OK) && debug) {
        syslog(LOG_DEBUG, "%s: can't get remote address from environment variable, result=%d", nssname, result);
    }

    // connect to all TACACS server in parallel
    // after any server authorized and set tacacs_auth_success to true, other connection will stop.
    min_tac_srv_latency_us = 0;
    for(srvr=0; srvr < tac_srv_no; srvr++) {
        pthread_t thread;
        tacacs_thread_args_t* args = malloc(sizeof(tacacs_thread_args_t));
        args->name = pb->name;
        args->srvr = srvr;
        args->remote_addr = remote_addr;
        args->current_tty = current_tty;
        pthread_create(&thread, NULL, lookup_tacacs_user_thread, args);
        
        // if all server are very fast, first server will finish first and will not request authentication to multiple server.
        usleep(1000 * TACACS_SERVER_DELAY_FACTOR);
    }

    // wait until one TACACS thread succeeded or all TACACS thread failed.
    while (!tacacs_auth_finish && (finish_server_count < tac_srv_no)) {
        usleep(1000);
    }

    if (tacacs_auth_success) {
        ret = got_tacacs_user(pb, server_priv_level);
        if(debug)
            syslog(LOG_DEBUG, "%s: TACACS+ successful for user %s."
                " local lookup %s", nssname, pb->name,
                ret == 0?"OK":"no match");
    }
    else if (finish_server_count == tac_srv_no) {
        ret = 1; /*  All tacacs server connect failed */
        if(debug)
            syslog(LOG_DEBUG, "%s: all TACACS+ server replies user %s"
                " invalid", nssname, pb->name);
    }

    return ret;
}

/*
 * This is an NSS entry point.
 * We implement getpwnam(), because we remap from the tacacs.
 *
 * We try the lookup to the tacacs server first.  If we can't make a
 * connection to the server for some reason, we also try looking up
 * the account name via the mapping file, primarily to handle cases
 * where we aren't running with privileges to read the tacacs configuration
 * (since it has the secret key).
 */
enum nss_status _nss_tacplus_getpwnam_r(const char *name, struct passwd *pw,
    char *buffer, size_t buflen, int *errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    int result;
    struct pwbuf pbuf;

    /*
     * When filename completion is used with the tab key in bash, getpwnam
     * is invoked. And the parameter "name" is '*'. In order not to connect to
     * TACACS+ server frequently, check user name whether is valid.
     */
    if(!strcmp(name, "*"))
        return NSS_STATUS_NOTFOUND;

    result = parse_config(config_file);

    if(result) {
        syslog(LOG_ERR, "%s: bad config or server line for nss_tacplus",
                nssname);
    }
    else if(0 == tac_srv_no) {
        syslog(LOG_WARNING, "%s: no tacacs server in config for nss_tacplus",
                nssname);
    }
    else if(is_non_tacacs_user(name)) {
       /* It is non-tacacs user, so bail out */
    }
    else {
        /* marshal the args for the lower level functions */
        pbuf.name = (char *)name;
        pbuf.pw = pw;
        pbuf.buf = buffer;
        pbuf.buflen = buflen;
        pbuf.errnop = errnop;

        if(0 == lookup_tacacs_user(&pbuf)) {
            status = NSS_STATUS_SUCCESS;
            if(debug)
                syslog(LOG_DEBUG, "%s: name=%s, pw_name=%s, pw_passwd=%s, pw_shell=%s",
                    nssname, name, pw->pw_name, pw->pw_passwd, pw->pw_shell);
        }
    }

    return status;
}
