#include "defs.h"
#include <sys/sendfile.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <stdint.h>
#include <fcntl.h>
#include <time.h>
#include <utmp.h>

//----------------------------------------------------------------------

static void QuitSignal (int sig);
static void AlarmSignal (int sig);
static void XreadySignal (int sig);
static void ChildSignal (int sig);
static void SetupUserResources (const struct account* acct);
static void BecomeUser (const struct account* acct);
static void RedirectToLog (const struct account* acct);
static void WriteMotd (const struct account* acct);
static void GenerateMCookie (uint8_t* cbuf);
static void WriteXauthority (const char* filename, unsigned dpy, const uint8_t* mcookie);
static pid_t LaunchX (const struct account* acct);
static pid_t LaunchShell (const struct account* acct, const char* arg);

//----------------------------------------------------------------------

static bool _quitting = false, _xready = false;
static int _killsig = SIGTERM;
static pid_t _shellpid = 0, _xpid = 0;
static uint8_t _xdisplay = 0;
static uint8_t _xmcookie [16] = {};
static char _userrundir [32] = {};
static char _usertmpdir [32] = {};
static char _xauthpath [64] = {};

//----------------------------------------------------------------------

void RunSession (const struct account* acct)
{
    SetupUserResources (acct);

    // Set session signal handlers that quit
    typedef void (*psigfunc_t)(int);
    psigfunc_t hupsig = signal (SIGHUP, QuitSignal),
	    termsig = signal (SIGTERM, QuitSignal),
	    quitsig = signal (SIGQUIT, QuitSignal),
	    alrmsig = signal (SIGALRM, AlarmSignal);
    signal (SIGCHLD, ChildSignal);

    // Check if need to launch X
    char xinitrcPath [PATH_MAX];
    snprintf (xinitrcPath, sizeof(xinitrcPath), "%s/.xinitrc", acct->dir);
    if (0 == access (xinitrcPath, R_OK))
	_xpid = LaunchX (acct);

    // Launch login shell; with .xinitrc if X is running
    _shellpid = LaunchShell (acct, _xpid ? ".xinitrc" : NULL);
    if (!_shellpid)
	return;
    WriteUtmp (acct, _shellpid, USER_PROCESS);

    sigset_t ssmask, ssorig;
    sigemptyset (&ssmask);
    sigaddset (&ssmask, SIGCHLD);
    sigaddset (&ssmask, SIGTERM);
    sigaddset (&ssmask, SIGQUIT);
    sigaddset (&ssmask, SIGALRM);
    sigaddset (&ssmask, SIGHUP);
    sigprocmask (SIG_BLOCK, &ssmask, &ssorig);

    // Wait until the child processes quit or the term signal
    while (_shellpid || _xpid) {
	sigsuspend (&ssorig);
	sigprocmask (SIG_BLOCK, &ssmask, NULL);
	if (_quitting) {
	    if (_shellpid)
		kill (_shellpid, _killsig);
	    if (_xpid)
		kill (_xpid, _killsig);
	}
    }
    sigprocmask (SIG_SETMASK, &ssorig, NULL);

    // Logout complete, note that shell is dead in utmp
    WriteUtmp (acct, _shellpid, DEAD_PROCESS);

    // Restore main signal handlers and cancel timeout, if any
    signal (SIGALRM, alrmsig);
    signal (SIGHUP, hupsig);
    signal (SIGQUIT, termsig);
    signal (SIGTERM, quitsig);
    alarm (0);
}

static void QuitSignal (int sig)
{
    syslog (LOG_INFO, "shutting down session on signal %d", sig);
    _quitting = true;
    alarm (KILL_TIMEOUT);
}

static void AlarmSignal (int sig __attribute__((unused)))
{
    syslog (LOG_WARNING, "session hung; switching to SIGKILL");
    _quitting = true;
    _killsig = SIGKILL;
}

static void XreadySignal (int sig __attribute__((unused)))
{
    _xready = true;
}

static void ChildSignal (int sig __attribute__((unused)))
{
    int chldstat = 0;
    pid_t cpid = waitpid (-1, &chldstat, WNOHANG);
    if ((cpid == _shellpid || cpid == _xpid) && (WIFEXITED(chldstat) || WIFSIGNALED(chldstat))) {
	if (cpid == _shellpid)
	    _shellpid = 0;
	else if (cpid == _xpid)
	    _xpid = 0;
	_quitting = true;
	alarm (KILL_TIMEOUT);
    }
}

static void SetupUserResources (const struct account* acct)
{
    // Create user tmp dir /tmp/user
    snprintf (_usertmpdir, sizeof(_usertmpdir), _PATH_TMP "%s", acct->name);
    if (0 != access (_usertmpdir, F_OK)) {
	mkdir (_usertmpdir, 0700);
	chown (_usertmpdir, acct->uid, acct->gid);
    }

    // Create XDG_RUNTIME_DIR in /run/user/uid
    snprintf (_userrundir, sizeof(_userrundir), "/run/user/%u", acct->uid);
    if (0 != access (_userrundir, F_OK)) {
	mkdir ("/run", 0755);
	mkdir ("/run/user", 0755);
	mkdir (_userrundir, 0700);
	chown (_userrundir, acct->uid, acct->gid);
    }

    // Determine X display to launch
    _xdisplay = _ttypath[strlen(_ttypath)-1]-'1';

    // Create Xauthority file for the user
    GenerateMCookie (_xmcookie);
    snprintf (_xauthpath, sizeof(_xauthpath), "%s/xdpy%u.auth", _userrundir, _xdisplay);
    WriteXauthority (_xauthpath, _xdisplay, _xmcookie);
    chown (_xauthpath, acct->uid, acct->gid);
}

static void BecomeUser (const struct account* acct)
{
    if (0 != setgid (acct->gid))
	perror ("setgid");
    if (0 != setuid (acct->uid))
	perror ("setuid");

    clearenv();
    setenv ("TERM", _termname, false);
    setenv ("PATH", _PATH_DEFPATH, false);
    setenv ("USER", acct->name, true);
    setenv ("SHELL", acct->shell, true);
    setenv ("HOME", acct->dir, true);
    setenv ("TMPDIR", _usertmpdir, true);
    setenv ("XDG_RUNTIME_DIR", _userrundir, false);
    char vtnr[2] = {'1'+_xdisplay,0};
    setenv ("XDG_VTNR", vtnr, false);
    static const struct { const char *name, *val; } c_Envs[] = {
	{ "XDG_SEAT", NULL },
	{ "XDG_SESSION_ID", NULL },
	{ "XDG_SESSION_TYPE", "tty" },
	{ "XDG_SESSION_CLASS", "user" },
	{ "DBUS_SESSION_BUS_ADDRESS", NULL }
    };
    for (unsigned i = 0; i < sizeof(c_Envs)/sizeof(c_Envs[0]); ++i) {
	const char* eval = PamGetenv (c_Envs[i].name);
	if (!eval)
	    eval = c_Envs[i].val;
	if (eval)
	    setenv (c_Envs[i].name, eval, true);
    }

    if (0 != chdir (acct->dir))
	perror ("chdir");
}

static void RedirectToLog (const struct account* acct)
{
    close (STDIN_FILENO);
    if (STDIN_FILENO != open (_PATH_DEVNULL, O_RDONLY))
	return;

    char logname [PATH_MAX];
    unsigned lnl = snprintf (logname, sizeof(logname), "%s/xsession-errors", _usertmpdir);
    if (lnl >= sizeof(logname))
	return;

    int fd = open (logname, O_WRONLY| O_CREAT| O_APPEND, S_IRUSR| S_IWUSR| S_IRGRP);
    if (fd < 0)
	return;
    dup2 (fd, STDOUT_FILENO);
    dup2 (fd, STDERR_FILENO);
    close (fd);
    chown (logname, acct->uid, acct->gid);
}

static void WriteMotd (const struct account* acct)
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

static void GenerateMCookie (uint8_t* cbuf)
{
    uint32_t* cubuf = (uint32_t*) cbuf;
    for (unsigned i = 0; i < 4; ++i)
	cubuf[i] = rand();
}

static void WriteXauthority (const char* filename, unsigned dpy, const uint8_t* mcookie)
{
    char host [HOST_NAME_MAX] = {};
    gethostname (host, sizeof(host));
    #define AUTH_TYPE	"MIT-MAGIC-COOKIE-1"
    uint16_t sz;
    const size_t hostlen = strlen(host),
		wbufsz = 5*sizeof(sz)+hostlen+1+strlen(AUTH_TYPE)+16;
    uint8_t wbuf [wbufsz];
    uint8_t* wp = wbuf;
    // First field is the address family, AF_LOCAL
    enum { XauthFamilyLocal = 256 };
    sz = htons(XauthFamilyLocal);	// All shorts in network byte order
    wp = mempcpy (wp, &sz, sizeof(sz));
    // Second is the hostname
    sz = htons(hostlen);
    wp = mempcpy (wp, &sz, sizeof(sz));
    wp = mempcpy (wp, host, hostlen);
    // Third is the display
    char dpychar = '0'+dpy;
    sz = htons(sizeof(dpychar));
    wp = mempcpy (wp, &sz, sizeof(sz));
    *wp++ = dpychar;
    // Fourth is the auth type
    sz = htons(strlen(AUTH_TYPE));
    wp = mempcpy (wp, &sz, sizeof(sz));
    wp = mempcpy (wp, AUTH_TYPE, strlen(AUTH_TYPE));
    // Fifth is the auth data
    sz = htons(16);
    wp = mempcpy (wp, &sz, sizeof(sz));
    wp = mempcpy (wp, mcookie, 16);

    int fd = open (filename, O_WRONLY| O_CREAT| O_TRUNC, 0600);
    if (fd >= 0) {
	size_t bw = write (fd, wbuf, wbufsz);
	if (0 != close (fd) || bw != wbufsz)
	    unlink (filename);
    }
}

static pid_t LaunchX (const struct account* acct)
{
    // Block delivery of SIGUSR1 and other message signals
    // until ready to avoid race conditions
    sigset_t ssmask, ssorig;
    sigemptyset (&ssmask);
    sigaddset (&ssmask, SIGUSR1);
    sigaddset (&ssmask, SIGCHLD);
    sigaddset (&ssmask, SIGTERM);
    sigaddset (&ssmask, SIGQUIT);
    sigaddset (&ssmask, SIGALRM);
    sigaddset (&ssmask, SIGHUP);
    sigprocmask (SIG_BLOCK, &ssmask, &ssorig);

    signal (SIGUSR1, XreadySignal);

    pid_t pid = fork();
    if (pid > 0) {
	for (;;) {	// Wait for SIGUSR1 from X before returning
	    sigsuspend (&ssorig);
	    sigprocmask (SIG_BLOCK, &ssmask, NULL);
	    int ecode, rc = waitpid (pid, &ecode, WNOHANG);
	    if ((rc == pid && WIFEXITED(ecode)) || (rc < 0 && errno != EINTR)) {
		_quitting = false;	//< try again with shell
		syslog (LOG_ERR, "X pid %d failed to start, error %d, falling back to plain shell", pid, ecode);
		pid = 0;
		break;
	    } else if (_xready)
		break;
	}
	sigprocmask (SIG_SETMASK, &ssorig, NULL);
	return pid;
    }

    // Child process or error, restore sigmask
    sigprocmask (SIG_SETMASK, &ssorig, NULL);
    if (pid < 0)
	ExitWithError ("fork");

    // Child process; change to user and exec the X
    RedirectToLog (acct);
    chdir ("/");

    signal (SIGTTIN, SIG_IGN);	// Ignore server reads and writes
    signal (SIGTTOU, SIG_IGN);
    signal (SIGUSR1, SIG_IGN);	// This tells the X server to send SIGUSR1 to parent when ready

    char dpyname[] = ":0", vtname[] = "vt01";
    dpyname[1] += _xdisplay;
    vtname[3] += _xdisplay;
    const char* argv[] = { "X", dpyname, vtname, "-quiet", "-nolisten", "tcp", "-auth", _xauthpath, NULL };
    if (0 != access (argv[7], R_OK))
	argv[6] = NULL;
    execv ("/usr/bin/X", (char* const*) argv);
    ExitWithError ("execv");
}

static pid_t LaunchShell (const struct account* acct, const char* arg)
{
    pid_t pid = fork();
    if (pid > 0)
	return pid;
    else if (pid < 0)
	ExitWithError ("fork");

    // Child process; change to user and exec the login shell
    BecomeUser (acct);
    if (arg) {	// If launching xinitrc, set DISPLAY
	char display[] = ":0";
	display[1] += _xdisplay;
	setenv ("DISPLAY", display, true);
	setenv ("XAUTHORITY", _xauthpath, true);
	setenv ("XDG_SESSION_TYPE", "x11", true);
	RedirectToLog (acct);
    }
    WriteMotd (acct);

    char shname [16];	// argv[0] of a login shell is "-bash"
    const char* shbasename = strrchr (acct->shell, '/');
    if (!shbasename++)
	shbasename = acct->shell;
    snprintf (shname, sizeof(shname), "-%s", shbasename);

    const char* argv[] = { shname, arg, NULL };
    execv (acct->shell, (char* const*) argv);
    ExitWithError ("execv");
}
