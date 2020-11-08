% PLEASE(1) please user manual
% Ed Neville (ed-please@s5h.net)
% 16 August 2020

# NAME

please.ini

# DESCRIPTION

The `please.ini` file contains the ACL for users of the `please` and `pleaseedit` programs.

All rules in `please.ini` will permit or deny based on command regex matches.

`please.ini` is an ini file, and as such it makes sense to label the sections with a good short description of what the section provides. You may then find this helpful when listing rights with `please -l`.

Rules are read and applied in the order they are presented in the configuration file. So if the user is permitted to run a command early in the file, but later a deny is matches against `.*`, then the user will not be permitted to run any command.

`%{USER}` will expand to the user who is currently running `please`, this enables a single rule for a group to modify/run something that matches their name.

The properties in ini permitted are as follows:

 * name=[regex], or user, mandatory
 * target=[regex] user to execute or list as, defaults to root
 * permit=[true|false] defaults to true
 * require_pass=[true|false], defaults to true
 * regex=[regex], is the regular expression that the command matches against, defaults to ^$
 * notbefore=[YYYYmmdd|YYYYmmddHHMMSS], defaults to never
 * notafter=[YYYYmmdd|YYYYmmddHHMMSS], defaults to never
 * datematch=[Day dd Mon HH:MM:SS UTC YYYY], regex to match against a date string
 * type=[edit/run/list], defaults to run, edit = pleaseedit entry, list = user access rights listing
 * group=[true|false] user, when true name refers to a group rather than a user
 * hostname=[regex], permitted hostnames where this may apply
 * dir=[regex], permitted regex for switchable directories
 * include=[file], read ini file, and continue to next section
 * includedir=[directory], read .ini files in directory, and continue to next section
 * editcmd=[program], run program after editor exits, if exit is zero, continue with file replacement
 * editmode=[octal mode], set replacement file to octal mode
 * reason=[true|false], require a reason for execution, defaults to false
 * last=[true|false], when true, stop processing if matched, defaults to false

`regex` is a regular expression.

Using an anchor (`^`) for the regex field will be as good as saying the rule should match any command.

If you wish to permit a user to view another's command set, then you may do this using `type=list` (run by default). To list another user, they must match the `target` regex.

# EXAMPLE

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
list=true
target=^(eng|net|dba)ops$
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
datematch = ^Thu\\s+1\\s+Oct\\s+22:00:00\\s+UTC\\s+2020
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

I welcome pull requests with open arms.

