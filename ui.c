// This file is part of the loginx project
//
// Copyright (c) 2013 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "defs.h"
#include <ncurses.h>
#include <ctype.h>

#ifndef COLOR_DEFAULT
    #define COLOR_DEFAULT -1
#endif

#define min(a,b)	((a)<(b)?(a):(b))

enum {
    MAX_PROMPT_WIDTH = sizeof(PASSWORD_PROMPT)-1,
    MAX_INPUT_WIDTH = sizeof(PASSWORD_MASKSTR),
    LOGIN_WINDOW_WIDTH = 1+1+MAX_PROMPT_WIDTH+1+MAX_INPUT_WIDTH+1+1,
    LOGIN_WINDOW_HEIGHT = 1+2+1
};

//----------------------------------------------------------------------

static WINDOW* _loginbox = NULL;

//----------------------------------------------------------------------

static void CursesInit (void);
static void CursesCleanup (void);

//----------------------------------------------------------------------

static void CursesInit (void)
{
    if (!initscr())
	ExitWithMessage ("failed to initialize curses");
    atexit (CursesCleanup);
    start_color();
    use_default_colors();
    init_pair (1, COLOR_GREEN, COLOR_DEFAULT);
    init_pair (2, COLOR_CYAN, COLOR_DEFAULT);
    noecho();
}

static void CursesCleanup (void)
{
    if (isendwin())
	return;
    if (_loginbox)
	delwin (_loginbox);
    endwin();
}

unsigned LoginBox (acclist_t al, char* password)
{
    CursesInit();

    if (!(_loginbox = newwin (LOGIN_WINDOW_HEIGHT, LOGIN_WINDOW_WIDTH, (LINES-LOGIN_WINDOW_HEIGHT)/2, (COLS-LOGIN_WINDOW_WIDTH)/2)))
	ExitWithMessage ("failed to create login window");
    keypad (_loginbox, true);
    nodelay (_loginbox, false);
    wbkgd (_loginbox, COLOR_PAIR(1)|' ');

    int key;
    unsigned pwlen = 0;
    const unsigned aln = NAccounts();
    if (!aln)
	ExitWithMessage ("no usable accounts found");
    memset (password, 0, MAX_PW_LEN);

    // Make last logged in user default
    unsigned ali = 0;
    for (unsigned i = 0; i < aln; ++i)
	if (al[ali]->ltime <= al[i]->ltime)
	    ali = i;

    do {
	wattrset (_loginbox, COLOR_PAIR(1));
	werase (_loginbox);
	box (_loginbox, 0, 0);
	mvwaddstr (_loginbox, 1,2, USERNAME_PROMPT);
	mvwaddstr (_loginbox, 2,2, PASSWORD_PROMPT);
	wattrset (_loginbox, COLOR_PAIR(2));
	mvwaddnstr (_loginbox, 1,2+sizeof(USERNAME_PROMPT), al[ali]->name, MAX_INPUT_WIDTH);
	mvwaddnstr (_loginbox, 2,2+sizeof(PASSWORD_PROMPT), PASSWORD_MASKSTR, min(strlen(PASSWORD_MASKSTR),pwlen));
	wrefresh (_loginbox);
	key = wgetch (_loginbox);
	if (isprint(key) && pwlen < MAX_PW_LEN-1)
	    password[pwlen++] = key;
	else if (key == KEY_BACKSPACE && pwlen > 0)
	    password[--pwlen] = 0;
	else if (key == KEY_UP)
	    ali = (ali-1) % aln;
	else if (key == KEY_DOWN || key == '\t')
	    ali = (ali+1) % aln;
    } while (key != '\n');

    delwin (_loginbox);
    CursesCleanup();

    return ali;
}

void ClearScreen (void)
{
    if (!isatty (STDOUT_FILENO))
	return;
    // Clear the screen; [r resets scroll region, [H homes cursor, [J erases
    #define RESET_SCREEN_CMD "\e[r\e[H\e[J"
    write (STDOUT_FILENO, RESET_SCREEN_CMD, sizeof(RESET_SCREEN_CMD));
}
