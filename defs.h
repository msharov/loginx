// This file is part of the loginx project
//
// Copyright (c) 2013 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#pragma once
#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <syslog.h>
#include <errno.h>
#include <paths.h>

enum { MAX_PW_LEN = 64 };

struct account {
    uid_t	uid;
    gid_t	gid;
    unsigned	ltime;
    char*	name;
    char*	dir;
    char*	shell;
};

typedef const struct account* const* acclist_t;

extern gid_t _ttygroup;
extern const char* _termname;
extern char _ttypath [16];

//----------------------------------------------------------------------

// loginx.c
void* xmalloc (size_t n);
void xfree (void* p);
#define xfreenull(pp)	do { xfree(pp); pp = NULL; } while(0)
void ExitWithError (const char* fn) __attribute__((noreturn));
void ExitWithMessage (const char* msg) __attribute__((noreturn));

// pam.c
void PamOpen (void);
void PamClose (void);
bool PamLogin (const struct account* acct, const char* password);
void PamLogout (void);
const char* PamGetenv (const char* name);

// uacct.c
acclist_t ReadAccounts (void);
unsigned NAccounts (void);
void ReadLastlog (void);
void WriteLastlog (const struct account* acct);
void WriteUtmp (const struct account* acct, pid_t pid, short uttype);

// ui.c
unsigned LoginBox (acclist_t al, char* password);
void ClearScreen (void);

// usess.c
void RunSession (const struct account* acct);
