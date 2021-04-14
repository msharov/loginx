# loginx

This is a combination of getty, login, and xinit for use on the Linux
console. A single executable is simpler and can do a few extra things
to require less typing during login.

Features:

- A curses-based login prompt. A nice thing to have for those of use who
  do not want to use xdm but find getty a little bare.
- Remembers last login name so you don't have to type it every time. In
  the login dialog press tab, up, or down, to cycle through available
  usernames. Very convenient on a family PC where security is not tight.
- Will launch X if you have ~/.xinitrc or your login shell otherwise. If
  X fails to start, loginx falls back to the plain shell.

loginx requires PAM, ncurses, and a c11-supporting compiler, gcc 4.6+:

```sh
./configure && make install
```

Use it like you would getty. The command is "loginx tty1", and you'd add
it to inittab, somewhere in rc.d, in a copy of systemd's getty@.service,
or whatever correct location your distribution's init system requires.

make install will by default install loginx@.service to the systemd
system directory. Enable with "systemctl enable loginx@tty1". You may
need to disable getty and display manager first.

Also, you'll need a valid PAM configuration file. make install will
install one that ought to work. If not, copy /etc/pam.d/login to
/etc/pam.d/loginx.
