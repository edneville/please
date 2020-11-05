% PLEASE(1) please user manual
% Ed Neville (ed-please@s5h.net)
% 16 August 2020

# NAME

please - a tool for access elevation.

# SYNOPSIS

```
please /bin/bash
please [-t/--target] backup tar -cvf - /home/data | ...
pleaseedit /etc/fstab
pleaseedit [-r/--reason] "new fs" /etc/fstab
please [-l/--list]
please [-l/--list] [-t/--target] user
please [-d/--dir] [dir] command
please [-n/--noprompt] command
please [-r/--reason] "sshd reconfigured, ticket 24365" /etc/init.d/ssh restart
please [-p/--purge]
please [-w/--warm]
```

# DESCRIPTION

please is a sudo clone that has regex support and a simple approach to ACL.

The aim is to allow admins to delegate accurate least privilege access with ease. There are times when what is intended to be executed can be expressed easily with a regex to expose only what is needed and nothing more.

Executing with `-d dir` will change directory to dir prior to execution. `-n` will force please to exit with 1 if please would require a password prior to execution. `-p` will purge an existing token for the running user, `-w` will warm the token and challenge authentication and immediately exit.

# EXAMPLES

Run a shell as the httpd user:

```
please -t httpd /bin/bash
```

To list what you may run:

```
please -l
```

Or with `username` to show what another user may run. username must match the regex in a `permit=list` rule.

```
please -l username
```

# FILES

/etc/please.ini

# CONTRIBUTIONS

I welcome pull requests with open arms.

# SEE ALSO

please.ini


