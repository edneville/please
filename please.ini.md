---
title: please.ini
section: 5
header: User Manual
footer: please 0.3.25
author: Ed Neville (ed-please@s5h.net)
date: 10 March 2021
---

# NAME

please.ini - configuration file for access

# DESCRIPTION

The **please.ini** file contains one or more **[sections]** that hold ACL for users of the **please** and **pleaseedit** programs.

`please.ini` is an ini file, sections can be named with a short description of what the section provides. You may then find this helpful when listing rights with **please -l**.

Rules are read and applied in the order they are presented in the configuration file. For example, if the user matches a permit rule to run a command in an early section, but in a later section matches criteria for a deny and no further matches, then the user will not be permitted to run that command. The last match wins.

The properties permitted are described below and should appear at most once per section. If a property is used more than once in a section, the last one will be used.

# SECTION OPTIONS

**[section-name]**
: section name, shown in list mode

**include=[file]**
: read ini file, and continue to next section

**includedir=[directory]**
: read .ini files in directory, and continue to next section

# MATCHES

**name=[regex]**
: mandatory, the user or **group** (see below) to match against

**target=[regex]**
: user to execute or list as, defaults to **root**

**regex=[regex]**
: the regular expression that the command or edit path matches against, defaults to ^$

**notbefore=[YYYYmmdd|YYYYmmddHHMMSS]**
: will add HHMMSS as 00:00:00 to the date if not given, defaults to never

**notafter=[YYYYmmdd|YYYYmmddHHMMSS]**
: will add 23:59:59 to the date if not given, defaults to never

**datematch=[Day dd Mon HH:MM:SS UTC YYYY]**
: regex to match a date string with

**type=[edit/run/list]**
: this section's mode behaviour, defaults to **run**, edit = **pleaseedit** entry, list = user access rights listing

**group=[true|false]**
: defaults to false, when true, the **name** (above) refers to a group rather than a user

**hostname=[regex]**
: permitted hostnames where this may apply, defaults to localhost

**dir=[regex]**
: permitted directories to run within

**regex** is a regular expression, **%{USER}** will expand to the user who is currently running `please`. This enables a single rule for a group to modify/run something that matches their name.

Spaces within arguments will be substituted as **'\\\ '** (backslash space). Use **^/bin/echo hello\\\\ world$** to match **/bin/echo "hello world"**, note that **\\** is a regex escape character so it must be escaped, therefore matching a space becomes **'\\\\\ '** (backslash backslash space).

# ACTIONS

**permit=[true|false]**
: permit or disallow the entry, defaults to true

**require_pass=[true|false]**
: if entry matches, require a password, defaults to true

**reason=[true|false]**
: require a reason for execution/edit, defaults to false

**last=[true|false]**
: if true, stop processing when entry is matched, defaults to false

**syslog=[true|false]**
: log this activity to syslog, defaults to true

**editmode=[octal mode]**
: (**type=edit**) set the file mode bits on replacement file to octal mode, defaults to 0600

**exitcmd=[program]**
: (**type=edit**) run program after editor exits as the root user, if exit is zero, continue with file replacement. **%{NEW}** and **%{OLD}** placeholders expand to new and old edit files

# EXAMPLES

To allow all commands, you can use a greedy match (**^.\*$**). You should reduce this to the set of acceptable commands though.

```
[user_jim_root]
name=jim
target=root
regex=^.*$
```

If you wish to permit a user to view another's command set, then you may do this using **type=list** (**run** by default). To list another user, they must match the **target** regex.

```
[user_jim_list_root]
name=jim
type=list
target=root
```

**type** may also be **edit** if you wish to permit a file edit with **pleaseedit**.

```
[user_jim_edit_hosts]
name=jim
type=edit
target=root
regex=^/etc/hosts$
```

Naming sections should help later when listing permissions.

Below, user **mandy** may run **du** without needing a password, but must enter her password for a **bash** running as root:

```
[mandy_du]
name = mandy
regex = ^(/usr)?/bin/du\s+.*$
require_pass = false
[mandy_some]
name = mandy
regex = ^(/usr)?/bin/bash$
require_pass = true
```

**regex** can include repetitions. To permit running **wc** to count the lines in the log files (we don't know how many there are) in **/var/log**. This sort of regex will allow multiple instances of a **()** group with **+**, which is used to define the character class **[a-zA-Z0-9-]+**, the numeric class **\d+** and the group near the end of the line. In other words, multiple instances of files in **/var/log** that may end in common log rotate forms **-YYYYMMDD** or **.N**.

This will permit commands such as the following, note how for efficiency find will combine arguments with **\+** into fewer invocations. **xargs** could have been used in place of **find**.

```
$ find /var/log -type f -exec please /usr/bin/wc {} \+
```

Here is a sample for the above scenario:

```
[user_jim_root_wc]
name=jim
target=root
permit=true
regex=^/usr/bin/wc (/var/log/[a-zA-Z0-9-]+(\.\d+)?(\s)?)+$
```

User jim may only start or stop a docker container:

```
[user_jim_root_docker]
name=jim
target=root
permit=true
regex=^/usr/bin/docker (start|stop) \S+
```

User ben may only edit **/etc/fstab**:

```
[ben_fstab]
name=ben
target=root
permit=true
type=edit
regex=^/etc/fstab$
```

User ben may list only users **eng**, **net** and **dba**:

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

When the user completes their edit, and the editor exits cleanly, if **exitcmd** is included then this program will run as root. If the program also exits cleanly then the temporary edit will be copied to the destination.

**%{OLD}** and **%{NEW}** will expand to the old (existing source) file and edit candidate, respectively. To verify a file edit, **ben**'s entry to check **/etc/hosts** after clean exit could look like this:

```
[ben_ops]
name=ben
permit=true
type=edit
regex=^/etc/hosts$
exitcmd=/usr/local/bin/check_hosts %{OLD} %{NEW}
```

**/usr/local/bin/check_hosts** takes two arguments, the original file as the first argument and the modify candidate as the second argument. If **check_hosts** terminates zero, then the edit is considered clean and the original file is replaced with the candidate. Otherwise the edit file is not copied and is left, **pleaseedit** will exit with the return value from **check_hosts**.

A common **exitcmd** is to check the validity of **please.ini**, shown below. This permits members of the **admin** group to edit **/etc/please.ini** if they provide a reason (**-r**). Upon clean exit from the editor the tmp file will be syntax checked.

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

For large environments it is not unusual for a third party to require access during a short time frame for debugging. To accommodate this there are the **notbefore** and **notafter** time brackets. These can be either **YYYYmmdd** or **YYYYmmddHHMMSS**.

The whole day is considered when using the shorter date form of **YYYYmmdd**.

Many enterprises may wish to permit periods of access to a user for a limited time only, even if that individual is considered to have a permanent role.

User joker can do what they want as root on 1st April 2021:

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

**datematch** matches against the date string **Day dd mon HH:MM:SS UTC Year**. This enables calendar style date matches.

Note that the day of the month (**dd**) will be padded with spaces if less than two characters wide.

You can permit a group of users to run **/usr/local/housekeeping/** scripts every Monday:

```
[l2_housekeeping]
name=l2users
group=true
target=root
permit=true
regex = /usr/local/housekeeping/.*
datematch = ^Mon\s+.*
```

# REASONS

When **reason=true**, require a reason before permitting edits or execution with the **-r** option to **please** and **pleaseedit**. Some organisations may prefer a reason to be logged when a command is executed. This can be helpful for some situations where something such as **mkfs** or **useradd** might be preferable to be logged against a ticket.

```
[l2_user_admin]
name=l2users
group=true
target=root
permit=true
reason=true
regex = ^/usr/sbin/useradd\s+-m\s+\w+$
```

# DIR

In some situations you may only want a command to run within a set of directories. The directory is specified with the **-d** argument to **please**. For example, a program may output to the current working directory.

```
[eng_build_aliases]
name=l2users
group=true
dir=^/etc/mail$
regex = ^/usr/local/bin/build_aliases$
```

# LAST

**last=true** stops processing at a match:

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

For simplicity, there is no need to process other configured rules if certain that the **l2users** group are safe to execute this. **last** should only be used in situations where there will never be something that could contradict the match in an undesired way later.

# SYSLOG

By default entries are logged to syslog. If you do not wish an entry to be logged then specify **syslog=false**. In this case **jim** can run anything in **/usr/bin/** as root and it will not be logged.

```
[maverick]
syslog = false
name = jim
regex = /usr/bin/.*
reason = false
```

# FILES

/etc/please.ini

# NOTES

At a later date repeated properties within the same section may be treated as a match list.

At a later date sections with names containing 'default' may behave differently to normal sections.

# CONTRIBUTIONS

I welcome pull requests with open arms. New features always considered.

# BUGS

Found a bug? Please either open a ticket or send a pull request/patch.

# SEE ALSO

**please**(1)
