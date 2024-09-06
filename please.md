---
title: please
section: 1
header: User Manual
footer: please 0.5.6
author: Ed Neville (ed-please@s5h.net)
date: 06 September 2024
---

# NAME

please - a tool for access elevation.

# SYNOPSIS

**please /bin/bash**

**pleaseedit /etc/fstab**

**pleaseedit [-r/\--reason \"new fs\"] /etc/fstab**

**pleaseedit [-g/\--group groupname] filename**

**pleaseedit [-t/\--target username] filename**

**pleaseedit [\--resume] filename**

**please [-a/\--allowenv list]**

**please [-c/\--check] /etc/please.ini**

**please [-d/\--dir directory] command**

**please [-e/\--env environment] command**

**please [-g/\--group groupname] command**

**please [-h/\--help]**

**please [-t/\--target username] backup tar -cvf - /home/data | ...**

**please [-u/\--user username] backup tar -cvf - /home/data | ...**

**please [-l/\--list]**

**please [-l/\--list] [-t/\--target username]**

**please [-l/\--list] [-u/\--user username]**

**please [-n/\--noprompt] command**

**please [-r/\--reason \"sshd reconfigured, ticket 24365\"] /etc/init.d/ssh restart**

**please [-p/\--purge]**

**please [-w/\--warm]**

# DESCRIPTION

**please** and **pleaseedit** are sudo alternatives that have regex support and a simple approach to ACL.

The aim is to allow admins to delegate accurate principle of least privilege access with ease. **please.ini** allows for very specific and flexible regex defined permissions.

**pleaseedit** adds a layer of safety to editing files. The file is copied to /tmp, where it can be updated. When **EDITOR** exits cleanly the file is copied alongside the target, the file will then be renamed over the original, but if a **exitcmd** is configured it must exit cleanly first. **resume** will continue editing when **exitcmd** fails.

**-a**/**\--allowenv list**
: allow environments separated by **,** to be passed through

**-c**/**\--check file**
: will check the syntax of a **please.ini** config file. Exits non-zero on error

**-d**/**\--dir**
: will change directory to **dir** prior to executing the command

**-g**/**\--group groupname**
: run or edit as groupname

**-h**/**\--help**
: print help and exit

**-l**/**\--list**
: to list rules

**-n**/**\--noprompt**
: will not prompt for authentication and exits with a status of 1

**-p**/**\--purge**
: will purge your current authentication token for the running user

**-r**/**\--reason** **[reason]**
: will add **reason** to the system log

**-t**/**\--target** **[username]**
: to execute command, or edit as target **username**

**-u**/**\--user** **[username]**
: to execute command, or edit as target **username**

**-v**/**\--version**
: print version and exit

**-w**/**\--warm**
: will warm an authentication token and exit

# EXAMPLE USAGE

**please -t httpd /bin/bash**
: run a shell as the httpd user

**please -l**
: to list what you may run

**please -t \"username\" -l**
: to show what username may run. **username** must match the target regex in a **type=list** rule

**please -r \'reloading apache2, change #123\' systemctl reload apache2**
: to reload apache2 with a reason

**pleaseedit -r \'adding new storage, ticket #24365\' /etc/fstab**
: to use pleaseedit to modify **fstab**

Please see **please.ini** for configuration examples.

# FILES

/etc/please.ini

# CONTRIBUTIONS

I welcome pull requests with open arms. New features always considered.

# BUGS

Found a bug? Please either open a ticket or send a pull request/patch.

# SEE ALSO

**please.ini**(5)

