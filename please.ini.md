---
title: please.ini
section: 5
header: User Manual
footer: please 0.3.20
author: Ed Neville (ed-please@s5h.net)
date: 23 January 2021
---

# NAME

please.ini - configuration file for access

# DESCRIPTION

The `please.ini` file contains the ACL for users of the `please` and `pleaseedit` programs.

All rules in `please.ini` will permit or deny based on command regex matches.

`please.ini` is an ini file, and as such it makes sense to label the sections with a good short description of what the section provides. You may then find this helpful when listing rights with `please -l`.

Rules are read and applied in the order they are presented in the configuration file. So if the user is permitted to run a command early in the file, but later a deny is matches against `.*`, then the user will not be permitted to run any command.

The properties in ini permitted are described below.

# SECTION OPTIONS

**[section-name]**
: section name, shown in list mode

**include=[file]**
: read ini file, and continue to next section

**includedir=[directory]**
: read .ini files in directory, and continue to next section

# MATCHES

**name=[regex]**
: mandatory, the user or **group** (see below) to match against.

**target=[regex]**
: user to execute or list as, defaults to root

**regex=[regex]**
: is the regular expression that the command matches against, defaults to ^$

**notbefore=[YYYYmmdd|YYYYmmddHHMMSS]**
: will add HHMMSS as 00:00:00 to the date if not given, defaults to never

**notafter=[YYYYmmdd|YYYYmmddHHMMSS]**
: will add 23:59:59 to the date if not given, defaults to never

**datematch=[Day dd Mon HH:MM:SS UTC YYYY]**
: regex to match against a date string

**type=[edit/run/list]**
: defaults to run, edit = pleaseedit entry, list = user access rights listing

**group=[true|false]**
: defaults to false, when true name refers to a group rather than a user

**hostname=[regex]**
: permitted hostnames where this may apply, defaults to localhost

**dir=[regex]**
: permitted regex for switchable directories, defaults to any

`regex` is a regular expression, `%{USER}` will expand to the user who is currently running `please`. This enables a single rule for a group to modify/run something that matches their name.

# ACTIONS

**exitcmd=[program]**
: run program after editor exits, if exit is zero, continue with file replacement. %{NEW} and %{OLD} placeholders expand to new and old edit files

**permit=[true|false]**
: permit or disallow the entry, defaults to true

**require_pass=[true|false]**
: if entry matches, require a password, defaults to true

**editmode=[octal mode]**
: set the file mode bits on replacement file to octal mode

**reason=[true|false]**
: require a reason for execution/edit, defaults to false

**last=[true|false]**
: if true, stop processing when entry is matched, defaults to false

**syslog=[true|false]**
: log this activity to syslog, defaults to true

# EXAMPLES

To allow all commands, you can use a greedy match (`^.*$`). You should probably reduce this to the set of acceptable commands though.

```
[user_ed_root]
name=ed
target=root
regex=^.*$
```

If you wish to permit a user to view another's command set, then you may do this using `type=list` (`run` by default). To list another user, they must match the `target` regex.

```
[user_ed_list_root]
name=ed
type=list
target=root
```

`type` may also be `edit` if you wish to permit a file edit with `pleaseedit`.

```
[user_ed_edit_hosts]
name=ed
type=edit
target=root
regex=^/etc/hosts$
```

Naming sections should help later when listing permissions.

`regex` can include repetitions. To permit running `wc` to count the lines in the log files in `/var/log` you can use the following:

```
[user_ed_root]
name=ed
target=root
permit=true
regex=^/usr/bin/wc (/var/log/[a-zA-Z0-9-]+(\.\d+)?(\s)?)+$
```

This sort of regex will allow multiple instances of a `()` group with `+`, which is used to define the character class `[a-zA-Z0-9-]+`, the numeric class `\d+` and the group near the end of the line. In other words, multiple instances of files in /var/log that may end in common log rotate forms `-YYYYMMDD` or `.N`.

This will permit commands such as the following, note how for efficiency find will combine arguments with `\+` into fewer invocations. `xargs` could have been used in place of `find`.

```
$ find /var/log -type f -exec please /usr/bin/wc {} \+
```

User `ed` may only start or stop a docker container:

```
[user_ed_root]
name=ed
target=root
permit=true
regex=^/usr/bin/docker (start|stop) \S+
```

User `ben` may only edit `/etc/fstab`:

```
[ben_fstab]
name=ben
target=root
permit=true
type=edit
regex=^/etc/fstab$
```

User `ben` may list only users `eng`, `net` and `dba` operators:

```
[ben_ops]
name=ben
permit=true
type=list
target=^(eng|net|dba)ops$
```

All users may list their own permissions. You may or may not wish to do this if you consider permitting a view of the rules to be a security risk.

```
[list_own]
name=^%{USER}$
permit=true
type=list
target=^%{USER}$
```

# EXITCMD

When the user completes their edit, and the editor exits cleanly, if `exitcmd` is included then the program will run. If the program also exits cleanly then the temporary edit will be copied to the destination.

%{OLD} and %{NEW} will expand to the old (existing source) file and edit candidate, respectively. To verify a file edit, `ben`'s entry to check `/etc/hosts` after clean exit could look like this:

```
[ben_ops]
name=ben
permit=true
type=edit
regex=^/etc/hosts$
exitcmd=/usr/local/bin/check_hosts %{OLD} %{NEW}
```

`/usr/local/bin/check_hosts` would take two arguments, the original file as the first argument and the modify candidate as the second argument. If `check_hosts` terminates zero, then the edit is considered clean and the original file is replaced with the candidate. Otherwise the edit file is not copied and is left, `pleaseedit` will exit with the return value from `check_hosts`.

A common `exitcmd` is to check the validity of `please.ini`, shown below. This permits members of the `admin` group to edit `/etc/please.ini` if they provide a reason (`-r`). Upon clean exit from the editor the tmp file will be syntax checked.

```
[please_ini]
name = admins
group = true
reason = true
regex = /etc/please.ini
type = edit
editmode = 600
exitcmd = /usr/bin/please -c %{NEW}
```

# DATED RANGES

For large environments it is not unusual for a third party to require access during a short time frame for debugging. To accommodate this there are the `notbefore` and `notafter` time brackets. These can be either `YYYYmmdd` or `YYYYMMDDHHMMSS`.

The whole day is considered when using the shorter date form of `YYYYMMDD`.

Many enterprises may wish to permit access to a user for a limited time only, even if that individual is in the role permanently.

User joker can do what they want as root on `1st April 2021`:

```
[joker_april_first]
name=joker
target=root
permit=true
notbefore=20210401
notafter=20210401
regex=^/bin/bash
```

# DATEMATCHES

Another date type is the `datematch` item, this constrains sections to a regex match against the date string `Day dd mon HH:MM:SS UTC Year`.

You can permit some a group of users to perform some house keeping on a Monday:

```
[l2_housekeeping]
name=l2users
group=true
target=root
permit=true
regex = /usr/local/housekeeping/.*
datematch = ^Thu\s+1\s+Oct\s+22:00:00\s+UTC\s+2020
```

# REASONS

When `true`, require a reason before permitting edits or execution with the `-r` option. Some organisations may prefer a reason to be logged when a command is executed. This can be helpful for some situations where something such as `mkfs` or `useradd` might be preferable to be logged against a ticket.

```
[l2_user_admin]
name=l2users
group=true
target=root
permit=true
reason=true
regex = ^/usr/sbin/useradd\s+-m\s+\w+$
```

# LAST

To stop processing at a match, `last=true` can be applied:

```
[mkfs]
name=l2users
group=true
target=root
permit=true
reason=true
regex = ^/sbin/mkfs.(ext[234]|xfs) /dev/sd[bcdefg]\d?$
last=true
```

For simplicity, there is no need to process other configured rules if certain that the `l2users` group are safe to execute this. `last` should only be used in situations where there will never be something that could contradict the match later.

# FILES

/etc/please.ini

# CONTRIBUTIONS

I welcome pull requests with open arms. New features always considered.

# BUGS

Found a bug? Please either open a ticket or send a pull request/patch.

# SEE ALSO

please
