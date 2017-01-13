// This file is part of the loginx project
//
// Copyright (c) 2013 by Mike Sharov <msharov@users.sourceforge.net>
// This file is free software, distributed under the MIT License.

#include "defs.h"
#include <security/pam_appl.h>
#include <grp.h>
#include <pwd.h>

//----------------------------------------------------------------------

static int xconv (int num_msg, const struct pam_message** msgm, struct pam_response** response, void* appdata_ptr);

//----------------------------------------------------------------------

static pam_handle_t* _pamh = NULL;
static const char* _username = NULL;
static const char* _password = NULL;	// Used only by xconv during PamLogin

//----------------------------------------------------------------------

static void verify (int r, const char* fn)
{
    if (r == PAM_SUCCESS)
	return;
    syslog (LOG_ERR, "%s: %s", fn, pam_strerror(_pamh,r));
    exit (EXIT_FAILURE);
}

static void PamSetEnvironment (void)
{
    const char* user = getlogin();
    if (user)
	pam_set_item (_pamh, PAM_RUSER, user);
    pam_set_item (_pamh, PAM_RHOST, "localhost");
    const char* tty = ttyname (STDIN_FILENO);
    if (tty)
	pam_set_item (_pamh, PAM_TTY, tty);
}

void PamOpen (void)
{
    static const struct pam_conv conv = { xconv, NULL };
    int r = pam_start (LOGINX_NAME, NULL, &conv, &_pamh);
    verify(r,"pam_start");
    PamSetEnvironment();
    atexit (PamClose);
}

void PamClose (void)
{
    if (!_pamh)
	return;
    if (_username)
	PamLogout();
    pam_end (_pamh, PAM_SUCCESS);
    _pamh = NULL;
}

bool PamLogin (const struct account* acct, const char* password)
{
    pam_set_item (_pamh, PAM_USER, acct->name);
    _password = password;	// Used only by xconv
    int r = pam_authenticate (_pamh, PAM_SILENT| PAM_DISALLOW_NULL_AUTHTOK);
    verify(r,"pam_authenticate");
    r = pam_acct_mgmt (_pamh, PAM_SILENT| PAM_DISALLOW_NULL_AUTHTOK);
    if (r == PAM_NEW_AUTHTOK_REQD) {
	r = pam_chauthtok(_pamh,PAM_CHANGE_EXPIRED_AUTHTOK);
	verify(r,"pam_chauthtok");
    }
    initgroups (acct->name, acct->gid);
    verify(r,"pam_acct_mgmt");
    r = pam_setcred(_pamh, PAM_SILENT| PAM_ESTABLISH_CRED);
    verify(r,"pam_setcred");
    r = pam_open_session (_pamh, PAM_SILENT);
    verify(r,"pam_open_session");
    pam_get_item (_pamh, PAM_USER, (const void**) &_username);
    _password = NULL;
    if (!_username || 0 != strcmp (_username, acct->name))
	return false;

    // Give ownership of the tty
    fchown (STDIN_FILENO, acct->uid, _ttygroup ? _ttygroup : acct->gid);
    fchmod (STDIN_FILENO, 0620);
    return true;
}

void PamLogout (void)
{
    if (!_username)
	return;

    // Retake ownership of the tty
    fchown (STDIN_FILENO, getuid(), _ttygroup ? _ttygroup : getgid());
    fchmod (STDIN_FILENO, 0620);

    pam_close_session (_pamh, PAM_SILENT);
    pam_setcred (_pamh, PAM_SILENT| PAM_DELETE_CRED);
    _username = NULL;
}

static int xconv (int num_msg, const struct pam_message** msgm, struct pam_response** response, void* appdata_ptr __attribute__((unused)))
{
    if (num_msg <= 0)
	return PAM_CONV_ERR;

    struct pam_response* reply = (struct pam_response*) calloc (num_msg, sizeof(struct pam_response));
    if (!reply)
	return PAM_CONV_ERR;

    for (int i = 0; i < num_msg; ++i) {
	switch (msgm[i]->msg_style) {
	    case PAM_PROMPT_ECHO_OFF:
	    case PAM_PROMPT_ECHO_ON:
		reply[i].resp = strdup(_password ? _password : "");
		reply[i].resp_retcode = 0;
		break;
	    case PAM_ERROR_MSG:
		syslog (LOG_ERR, "%s", msgm[i]->msg);
		break;
	    case PAM_TEXT_INFO:
		syslog (LOG_INFO, "%s", msgm[i]->msg);
		break;
	    default:	// Anything else fails login
		for (int j = 0; j < num_msg; ++j) {
		    if (reply[j].resp) {
			memset (reply[j].resp, 0, strlen(reply[j].resp));
			free (reply[j].resp);
			reply[j].resp = NULL;
		    }
		}
		free(reply);
		syslog (LOG_ERR, "unhandled PAM conversation style %d: %s", msgm[i]->msg_style, msgm[i]->msg);
		return PAM_CONV_ERR;
	}
    }
    *response = reply;
    return PAM_SUCCESS;
}
