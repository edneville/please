---
title: please
section: 1
header: User Manual
footer: please 0.3.21
author: ed neville (ed-please@s5h.net)
date: 27 January 2021
---

# NAME

please - a tool for access elevation.

# SYNOPSIS

**please /bin/bash**

**please [-c/\--check] /etc/please.ini**

**please [-d/\--dir] [dir] command**

**please [-h/\--help]**

**please [-t/\--target] backup tar -cvf - /home/data | ...**

**pleaseedit /etc/fstab**

**pleaseedit [-r/\--reason \"new fs\"] /etc/fstab**

**please [-l/\--list]**

**please [-l/\--list] [-t/\--target user]**

**please [-n/\--noprompt] command**

**please [-r/\--reason \"sshd reconfigured, ticket 24365\"] /etc/init.d/ssh restart**

**please [-p/\--purge]**

**please [-w/\--warm]**

# DESCRIPTION

`please` is a sudo clone that has regex support and a simple approach to ACL.

The aim is to allow admins to delegate accurate least privilege access with ease. There are times when what is intended to be executed can be expressed easily with a regex to expose only what is needed and nothing more.

`pleaseedit` allows safe editing of files. The file is copied to /tmp, where it can be updated. When `EDITOR` exits cleanly the file is copied alongside the target and then renamed.

`-c`/`--check file`
: will check the syntax of a `please.ini` config file. Exits non-zero on error.

`-d`/`--dir`
: will change the directory prior to executing the command in that location.

`-l`/`--list`
: to list rules.

`-n`/`--noprompt`
: will not prompt for authentication and exits with a status of 1.

`-r`/`--reason` `[reason]`
: will add `reason` to the system log.

`-p`/`--purge`
: will purge your current authentication token for the running user.

`-t`/`--target` `[user]`
: to execute command as target user.

`-w`/`--warm`
: will warm an authentication token and exit.

# EXAMPLES

`please -t httpd /bin/bash`
: run a shell as the httpd user.

`please -l`
: to list what you may run.

`please -t username -l`
: to show what username may run. `username` must match the target regex in a `type=list` rule.

`please -r "reloading httpd for ticket #123" systemctl reload apache2`
: to show what username may run. `username` must match the target regex in a `type=list` rule.

Please see `please.ini` for configuration examples.

# FILES

/etc/please.ini

# CONTRIBUTIONS

I welcome pull requests with open arms. Do please raise a ticket if you find a bug or would like to improve please in some way.

# SEE ALSO

please.ini


