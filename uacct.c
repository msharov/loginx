// This file is part of the loginx project
//
// Copyright (c) 2013 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "defs.h"
#include <pwd.h>
#include <grp.h>
#include <utmp.h>
#include <fcntl.h>
#include <time.h>
#include <sys/sendfile.h>

static struct account** _accts = NULL;
static unsigned _naccts = 0;
gid_t _ttygroup = 0;

static void CleanupAccounts (void)
{
    if (!_accts)
	return;
    for (unsigned i = 0; i < _naccts; ++i) {
	xfree (_accts[i]->name);
	xfree (_accts[i]->dir);
	xfree (_accts[i]->shell);
	xfree (_accts[i]);
    }
    xfreenull (_accts);
}

static bool CanLogin (const struct passwd* pw)
{
    return (pw->pw_shell && strcmp(pw->pw_shell, "/bin/false") && strcmp(pw->pw_shell,"/sbin/nologin"));
}

acclist_t ReadAccounts (void)
{
    _ttygroup = getgid();
    struct group* ttygr = getgrnam("tty");
    if (ttygr)	// If no tty group, use user's primary group
	_ttygroup = ttygr->gr_gid;
    endgrent();

    unsigned nac = 0;
    setpwent();
    for (struct passwd* pw; (pw = getpwent());)
	nac += CanLogin (pw);
    _accts = (struct account**) xmalloc ((nac+1)*sizeof(struct account*));
    atexit (CleanupAccounts);
    nac = 0;
    setpwent();
    for (struct passwd* pw; (pw = getpwent());) {
	if (!CanLogin (pw))
	    continue;
	_accts[nac] = (struct account*) xmalloc (sizeof(struct account));
	_accts[nac]->uid = pw->pw_uid;
	_accts[nac]->gid = pw->pw_gid;
	_accts[nac]->name = strdup (pw->pw_name);
	_accts[nac]->dir = strdup (pw->pw_dir);
	_accts[nac]->shell = strdup (pw->pw_shell);
	++nac;
    }
    endpwent();
    _naccts = nac;
    return ((acclist_t) _accts);
}

unsigned NAccounts (void)
{
    return (_naccts);
}

void ReadLastlog (void)
{
    int fd = open (_PATH_LASTLOG, O_RDONLY);
    if (fd < 0)
	return;
    struct stat st;
    if (fstat (fd, &st) == 0) {
	const unsigned maxuid = st.st_size / sizeof(struct lastlog);
	for (unsigned i = 0; i < _naccts; ++i)
	    if (_accts[i]->uid < maxuid)
		pread (fd, &_accts[i]->ltime, sizeof(_accts[i]->ltime), _accts[i]->uid * sizeof(struct lastlog));
    }
    close (fd);
}

void WriteLastlog (const struct account* acct)
{
    int fd = open (_PATH_LASTLOG, O_WRONLY| O_CREAT, 644);
    if (fd < 0)
	return;

    struct lastlog ll;
    memset (&ll, 0, sizeof(ll));
    ll.ll_time = time(NULL);
    strncpy (ll.ll_line, _ttypath, sizeof(ll.ll_line)-1);
    gethostname (ll.ll_host, sizeof(ll.ll_host)-1);

    pwrite (fd, &ll, sizeof(ll), acct->uid*sizeof(ll));

    close (fd);
}

void WriteUtmp (const struct account* acct)
{
    struct utmp ut;
    memset (&ut, 0, sizeof(ut));
    ut.ut_type = LOGIN_PROCESS;
    ut.ut_pid = getpid();
    strncpy (ut.ut_line, _ttypath, sizeof(ut.ut_line)-1);
    strncpy (ut.ut_user, acct->name, sizeof(ut.ut_user)-1);
    gethostname (ut.ut_host, sizeof(ut.ut_host)-1);
    struct timeval tv;
    gettimeofday (&tv, NULL);
    ut.ut_tv.tv_sec = tv.tv_sec;
    ut.ut_tv.tv_usec = tv.tv_usec;

    utmpname (_PATH_UTMP);
    setutent();
    pututline (&ut);
    endutent();

    updwtmp (_PATH_WTMP, &ut);
}

void WriteMotd (const struct account* acct)
{
    ClearScreen();
    int fd = open ("/etc/motd", O_RDONLY);
    if (fd < 0)
	return;
    struct stat st;
    if (fstat (fd, &st) == 0 && S_ISREG(st.st_mode))
	sendfile (STDOUT_FILENO, fd, NULL, st.st_size);
    close (fd);
    const time_t lltime = acct->ltime;
    printf ("Last login: %s\n", ctime(&lltime));
    fflush (stdout);
}
