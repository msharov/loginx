// This file is part of the loginx project
//
// Copyright (c) 2013 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the ISC license.

#include "defs.h"
#include <pwd.h>
#include <signal.h>
#include <time.h>
#include <locale.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/kd.h>
#include <fcntl.h>
#include <utmp.h>

//----------------------------------------------------------------------

static void InitEnvironment (void);
static int  OpenTTYFd (void);
static void OpenTTY (void);
static void ResetTerminal (void);

//----------------------------------------------------------------------

const char* _termname = "linux";
char _ttypath [16];

//{{{ Signal handling --------------------------------------------------

#define S(s) (1u<<(s))
enum {
    sigset_Quit	= S(SIGINT)|S(SIGQUIT)|S(SIGTERM)|S(SIGPWR)|
		S(SIGILL)|S(SIGABRT)|S(SIGBUS)|S(SIGFPE)|
		S(SIGSYS)|S(SIGSEGV)|S(SIGALRM)|S(SIGXCPU),
    qc_ShellSignalQuitOffset = 128
};

static void OnSignal (int s)
{
    static bool s_DoubleSignal = false;
    if (!s_DoubleSignal) {
	s_DoubleSignal = true;
	alarm(1);
	if (s != SIGTERM)
	    syslog (LOG_ERR, "exiting on signal %s", strsignal(s));
	exit (s+qc_ShellSignalQuitOffset);
    }
    _exit (s+qc_ShellSignalQuitOffset);
}

static void InstallCleanupHandlers (void)
{
    for (unsigned i = 0; i < NSIG; ++i)
	if (S(i) & sigset_Quit)
	    signal (i, OnSignal);
}
#undef S

//}}}-------------------------------------------------------------------
//{{{ Utility functions

void* xmalloc (size_t n)
{
    void* p = calloc (1, n);
    if (!p) {
	puts ("Error: out of memory");
	exit (EXIT_FAILURE);
    }
    return p;
}

void xfree (void* p)
{
    if (p)
	free (p);
}

void ExitWithError (const char* fn)
{
    syslog (LOG_ERR, "%s: %s", fn, strerror(errno));
    exit (EXIT_FAILURE);
}

void ExitWithMessage (const char* msg)
{
    syslog (LOG_ERR, "%s", msg);
    exit (EXIT_FAILURE);
}

// Randomly initializes the random number generator
static void srandrand (void)
{
    struct timespec now;
    clock_gettime (CLOCK_REALTIME, &now);
    unsigned seed = now.tv_sec;
    seed = (seed<<16)|(seed>>16);
    seed ^= now.tv_nsec;
    srand (seed);
}

//}}}-------------------------------------------------------------------

int main (int argc, const char* const* argv)
{
    InstallCleanupHandlers();
    srandrand();

    openlog (LOGINX_NAME, LOG_ODELAY, LOG_AUTHPRIV);

    const char* ttyname = (argc > 1 ? argv[1] : "tty1");
    snprintf (_ttypath, sizeof(_ttypath), _PATH_DEV "%s", ttyname);
    if (argc > 3)
	_termname = argv[3];

    InitEnvironment();
    OpenTTY();
    ResetTerminal();
    acclist_t al = ReadAccounts();
    ReadLastlog();

    char password [MAX_PW_LEN];
    unsigned ali = LoginBox (al, password);
    PamOpen();
    bool loginok = PamLogin (al[ali], password);
    memset (password, 0, sizeof(password));
    if (!loginok)
	return EXIT_FAILURE;

    WriteLastlog (al[ali]);
    WriteUtmp (al[ali], getpid(), LOGIN_PROCESS);
    if (!al[ali]->uid)	// The login strings are copied from util-linux login to allow log grepping compatibility
	syslog (LOG_NOTICE, "ROOT LOGIN ON %s", ttyname);
    else
	syslog (LOG_INFO, "LOGIN ON %s BY %s", ttyname, al[ali]->name);

    RunSession (al[ali]);

    WriteUtmp (al[ali], getpid(), DEAD_PROCESS);
    PamLogout();
    PamClose();
    ResetTerminal();
    return EXIT_SUCCESS;
}

static void InitEnvironment (void)
{
    for (unsigned f = 0, fend = getdtablesize(); f < fend; ++f)
	close (f);
    // ExitWithError will open syslog fd as stdin, but that's ok because it quits right after
    if (0 != chdir ("/"))
	ExitWithError ("chdir");
    if (getsid(0) != getpid())
	if (setsid() < 0)
	    ExitWithError ("setsid");
    setenv ("TERM", _termname, true);
}

static int OpenTTYFd (void)
{
    // O_NOCTTY is needed to use TIOCSCTTY, which will steal the tty control from any other pgrp
    int fd = open (_ttypath, O_RDWR| O_NOCTTY, 0);
    if (fd < 0)
	ExitWithError ("open");

    if (!isatty (fd))
	ExitWithMessage (LOGINX_NAME " must run on a tty");
    struct stat ttyst;
    if (fstat (fd, &ttyst))
	ExitWithError ("fstat");
    if (!S_ISCHR(ttyst.st_mode))
	ExitWithMessage ("the tty is not a character device");

    // Establish as session leader and tty owner
    if (getpgid(0) != tcgetsid(fd))
	if (ioctl (fd, TIOCSCTTY, 1) < 0)
	    ExitWithError ("failed to take tty control");
    return fd;
}

static void OpenTTY (void)
{
    // First time open tty to make it controlling terminal and vhangup
    int fd = OpenTTYFd();
    // Now close it and vhangup to eliminate all other processes on this tty
    close (fd);
    signal (SIGHUP, SIG_IGN);	// To not be killed by vhangup
    vhangup();
    signal (SIGHUP, OnSignal);	// To be killed by init

    // Reopen the tty and establish standard fds
    fd = OpenTTYFd();
    if (fd != STDIN_FILENO)	// All fds must be closed at this point
	ExitWithError ("open stdin");
    if (dup(fd) != STDOUT_FILENO || dup(fd) != STDERR_FILENO)
	ExitWithError ("open stdout");
    if (tcsetpgrp (STDIN_FILENO, getpgrp()))
	ExitWithError ("tcsetpgrp");
}

static void ResetTerminal (void)
{
    //
    // If keyboard is in raw state, unset it
    //
    int kbmode = K_XLATE;
    if (0 == ioctl (STDIN_FILENO, KDGKBMODE, &kbmode))
	if (kbmode != K_XLATE && kbmode != K_UNICODE)
	    ioctl (STDIN_FILENO, KDSKBMODE, kbmode = K_XLATE);
    setlocale (LC_ALL, kbmode == K_XLATE ? "C" : "C.UTF-8");

    //
    // Reset normal terminal settings.
    //
    struct termios ti;
    if (0 > tcgetattr (STDIN_FILENO, &ti))
	ExitWithError ("tcgetattr");
    // Overwrite known fields with sane defaults
    ti.c_iflag = ICRNL| IXON| BRKINT| IUTF8;
    ti.c_oflag = ONLCR| OPOST;
    ti.c_cflag = HUPCL| CREAD| CS8| B38400;
    ti.c_lflag = ISIG| ICANON| ECHO| ECHOE| ECHOK| ECHOCTL| ECHOKE| IEXTEN;
    #define TCTRL(k) k-('A'-1)
    static const cc_t c_CtrlChar[NCCS] = {
	[VINTR]		= TCTRL('C'),
	[VQUIT]		= TCTRL('\\'),
	[VERASE]	= 127,
	[VKILL]		= TCTRL('U'),
	[VEOF]		= TCTRL('D'),
	[VMIN]		= 1,
	[VSUSP]		= TCTRL('Z'),
	[VREPRINT]	= TCTRL('R'),
	[VDISCARD]	= TCTRL('O'),
	[VWERASE]	= TCTRL('W'),
	[VLNEXT]	= TCTRL('V'),
    };

    memcpy (ti.c_cc, c_CtrlChar, sizeof(ti.c_cc));

    // Remove this when non-vc terminals are not supported
    const char* termname = getenv("TERM");
    if (!termname || 0 != strcmp (termname, "linux"))
	ti.c_cc[VERASE] = TCTRL('H');
    #undef TCTRL

    if (0 > tcsetattr (STDIN_FILENO, TCSANOW, &ti))
	ExitWithError ("tcsetattr");

    ClearScreen();
}
