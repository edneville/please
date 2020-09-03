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

 * name=regex, or user, mandatory
 * target=regex user, defaults to ^root$
 * permit=[true|false] defaults to true
 * require_pass=[true|false], defaults to true
 * rule=regex, mandatory, is the regular expression that applies to this section
 * list=[true|false], defaults to false
 * edit=[true|false], defaults to false
 * notbefore=[YYYYmmdd|YYYYmmddHHMMSS], defaults to never
 * notafter=[YYYYmmdd|YYYYmmddHHMMSS], defaults to never
 * group=[true|false] user, when true name refers to a group rather than a user
 * hostname

`regex` is a regular expression.

Using an anchor (`^`) for the regex field will be as good as saying the rule should match any command.

If you wish to permit a user to view another's command set, then you may do this using the `list` flag (off by default). Users must match the regex.

# EXAMPLE

User `ed` may only start or stop a docker container:

```
[user_ed_root]
user=ed
target=root
permit=true
regex=^/usr/bin/docker (start|stop) \S+
```

User `ben` may only edit `/etc/fstab`:

```
[ben_fstab]
user=ben
target=root
permit=true
edit=true
regex=^/etc/fstab$
```

User joker can do what they want as root on `1st April 2021`:

```
[joker_april_first]
user=joker
target=root
permit=true
notbefore=20210401
notafter=20210401
regex=^/bin/bash
```

User `ben` may list only users `eng`, `net` and `dba` operators:

```
[ben_ops]
user=ben
permit=true
list=true
regex=^(eng|net|dba)ops$
```

# DATED RANGES

For large environments it is not unusual for a third party to require access during a short time frame for debugging. To accommodate this there are the `notbefore` and `notafter` time brackets. These can be either `YYYYmmdd` or `YYYYMMDDHHMMSS`.

The whole day is considered when using the shorter date form of `YYYYMMDD`.

Many enterprises may wish to permit access to a user for a limited time only, even if that individual is in the role permanently.

# FILES

/etc/please.conf

# CONTRIBUTIONS

I welcome pull requests with open arms.

