# Please, a sudo alternative with regex support

Great! This is what I need.

The aim is to allow admins to delegate accurate least privilege access with ease. There are times when what is intended to be executed can be expressed easily with a regex to expose only what is needed and nothing more.

The idea is to help you admin your box without giving users full root shells, just because that is easier. Most admins have experience of regex in one form or another, so lets configure access that way.

I saw regex but don't like regex. No problem, you can still use please without regex using `exact_` counterparts, or treat each field/property as plain text, and escape control characters `?(){}[]+` etc. Most of the regex match statements have `exact` counterparts.

Please is written with memory safe rust. Traditional C memory unsafety is avoided, logic problems may still exist. Logic problems would exist in both systems, but I choose the smaller problem set.

# How do I install it

It might already be in the repo that you're using:

[![Packaging status](https://repology.org/badge/vertical-allrepos/pleaser.svg)](https://repology.org/project/pleaser/versions)

If not, it is a simple install:

```
git clone https://gitlab.com/edneville/please.git
cd please
cargo test && cargo build --release \
&& install -oroot -groot -D -m4755 target/release/please target/release/pleaseedit /usr/local/bin
```

Arch:

```
pacman -Syu git fakeroot devtools binutils gcc rust 
git clone https://aur@aur.archlinux.org/pleaser.git
cd pleaser && makepkg -isr
```

Debian/Ubuntu:

```
apt install pleaser
```

Fedora (35):

```
dnf install pleaser
```

NetBSD:

```
pkgin install pleaser
```

SUSE Tumbleweed:

```
zypper install pleaser
```

RHEL 7 (EPEL):
```
yum install cargo git pam-devel
git clone 'https://gitlab.com/edneville/please.git'
cd please/
cargo test && cargo build --release && install -oroot -groot -D -m4755 target/release/please target/release/pleaseedit /usr/local/bin
```

Optionally, set `sudo` as an alias of `please`:

```
alias sudo="please"
alias sudoedit="pleaseedit"
```

Or, if you like, symlink in local:

```
cd /usr/local/bin && ln -s /usr/local/bin/please sudo && ln -s /usr/local/bin/pleaseedit sudoedit
```

# How do I set it up

You may need to configure PAM if you didn't use a distro package in order for `require_pass` to authenticate. Debian-based needs something similar to this in `/etc/pam.d/please` and `/etc/pam.d/pleaseedit`:

```
#%PAM-1.0
@include common-auth
@include common-account
@include common-session-noninteractive
```

Red Hat based needs something similar to this in the same files:

```
#%PAM-1.0
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    optional     pam_keyinit.so revoke
session    required     pam_limits.so
session    include      system-auth
```

Next, configure your `/etc/please.ini`, replace user names with appropriate values. The `ini` is divided into section options, matches and actions.

## Section options

| Part                        | Effect       |
|-----------------------------|--------------|
| [section-name]              | Section name, shown in list mode |
| include=file                | Include file as another ini source, other options will be skipped in this section. |
| includedir=dir              | Include dir of `.ini` files as other sources, in ascii sort order other options will be skipped in this section. Files not matching `.ini` will be ignored to allow for editor tmp files. |

`include` and `includedir` will override mandatory arguments.

## Matches

One of the simplest, that does not require password authentication can be defined as follows, assuming the user is `jim`:

The options are as follows:

| Part                        | Effect       |
|-----------------------------|--------------|
| name=regex                  | Mandatory, apply configuration to this entity. |
| target=regex                | May become these users. |
| rule=regex                  | This is the command regex for the section, default is ^$ |
| notbefore=YYYYmmdd          | The date, or YYYYmmddHHMMSS when this rule becomes effective. |
| notafter=YYYYmmdd           | The date, or YYYYmmddHHMMSS when this rule expires. |
| datematch=[Day dd Mon HH:MM:SS UTC YYYY] | regex to match against a date string |
| type=[edit/run/list]        | Set the entry type, run = execution, edit = pleaseedit, list = show user rights |
| group=[true/false]          | True to signify that name= refers to a group rather than a user. |
| hostname=regex              | Hosts where this applies, defaults to 'localhost'. |
| dir=regex                   | Permit switching to regex defined directory prior to execution. |
| reason=[true/false]         | when true, require a reason to be provided by `-r`, defaults to false |
| permit_env=regex            | when combined with `-a`, permit matching environments keys |

Exact counterparts, which must match exactly. When both regex and exact rules are present, the exact rule match will have precedence.

| Part                        | Effect       |
|-----------------------------|--------------|
| exact_name=string           | Match this exact name |
| exact_hostname=string       | Match this exact hostname |
| exact_target=string         | Match this exact target user |
| exact_rule=string           | Match this exact rule |
| exact_dir=string            | Match this exact directory |

## Actions

| Part                        | Effect       |
|-----------------------------|--------------|
| permit=[true/false]         | Defaults to true |
| require_pass=[true/false]   | Defaults to true, mandatory in run and edit, become this user |
| last=[true/false]           | when true, stop processing when matched, defaults to false |
| syslog=[true/false]         | log this activity to syslog, default = true |
| env_assign.key=value        | force environment **key** to be assigned **value** |
| exitcmd=[program]           | (edit) continue with file replacement if `program` exits 0 |
| editmode=[octal mode/keep]  | (edit) set destination file mode to `octal mode`, or keep the mode of an existing file. If the file is not present, or mode is not declared, then mode falls back to 0600. If there is a file present, then the mode is read and used just prior to file rename |

Using a greedy `.*` for the regex field will be as good as saying the rule should match any command. In previous releases there was no anchor (`^` and `$`) however, it seems more sensible to follow `find`'s approach and insist that there are anchors around the regex. This avoids `/bin/bash` matching `/home/user/bin/bash` unless the rule permits something like `/home/%{USER}/bin/bash`.

If a `include` directive is met, no other entries in the section will be processed. The same goes for `includedir`.

The ordering of rules matters. The last match will win. Set `permit=false` if you wish to exclude something, but this should be very rare as the permit should be against a regex rather than using a positive and then a negative match. A rule of best practice is to avoid a fail open and then try and exclude most of the universe.

For example, using the two entries below:

```
[jim_root_du]
name=jim
target=root
permit=true
rule = ^(/usr)?/bin/du (/home/[a-z0-9-]+\s?)+
require_pass=false
```

```
[jim_postgres]
name=jim
target=postgres
permit=true
rule = /bin/bash
require_pass=false
```

Would permit running `du`, as `/usr/bin/du` or `/bin/du` as `root`:

```
$ please du /home/*
```

And would also permit running a bash shell as `postgres`:

```
$ please -t postgres /bin/bash
postgres$
```

# Date ranges

For large environments it is not unusual for a third party to require access during a short time frame for debugging. To accommodate this there are the `notbefore` and `notafter` time brackets. These can be either `YYYYMMDD` or `YYYYMMDDHHMMSS`.

The whole day is considered when using the shorter date form of `YYYYMMDD`.

Many enterprises may wish to permit access to a user for a limited time only, even if that individual is in the role permanently.

# Date matches

Another date type is the `datematch` item, this constrains sections to a regex match against the date string `Day dd Mon HH:MM:SS UTC Year`.

You can permit some a group of users to perform some house keeping on a Monday:

```
[l2_housekeeping]
name=l2users
group=true
target=root
permit=true
rule = /usr/local/housekeeping/tidy_(logs|images|mail)
datematch = ^Mon.*
```

# pleaseedit

`pleaseedit` enables editing of files as another user. Enable editing rather than execution with `type=edit`. The first argument will be passed to `EDITOR`.

By default file permission bits will mirror existing file permissions.

This is performed as follows:

1. user runs edit as `pleaseedit -u root /etc/fstab`
2. `/etc/fstab` is copied to `/tmp/pleaseedit.$USER.r8cYph9h._etc_fstab`
3. user's `EDITOR` is executed against `/tmp/pleaseedit.$USER.r8cYph9h._etc_fstab`
4. if `EDITOR` exits 0, and `exitcmd` exits 0, then `/tmp/pleaseedit.$USER.r8cYph9h._etc_fstab` is copied to `/etc/fstab.llD3wRQB.pleaseedit.copy.$USER`
5.  `/etc/fstab.llD3wRQB.pleaseedit.copy.$USER` is set as (target) root owned and `renamed` to `/etc/fstab`

# exitcmd

exitcmd can be used prior to the tmp edit file move to the source location. This can be used to test configuration files are valid prior to renaming in place.

For something similar to apache, consider copying the config tree to a tmp directory before running the test to accommodate includes.

# Other examples

Members of the `audio` group may remove temporary users that an application may not have cleaned up in the form of `username_tmp.<10 random alphanumerics>` using `userdel`:

```
[user_remove_tmp_user]
name = audio
group = true
permit = true
require_pass = false
rule = /usr/sbin/userdel -f -r %{USER}_tmp\.[a-zA-Z0-9]{10}
```

How about, for the purpose of housekeeping, some users may be permitted to destroy zfs snapshots that look roughly like they're date stamped:

```
[user_remove_snapshots]
name = data
group = true
permit = true
require_pass = false
rule = /usr/sbin/zfs destroy storage/photos@\d{8}T\d{6}
```

To list what you may or may not do:

```
$ please -l
You may run the following:
  file: /etc/please.ini
    ed_root_list:root: ^.*$
You may edit the following:
  file: /etc/please.ini
    ed_edit_ini:root: ^/etc/please.ini$
```

The above output shows that I may run anything and may edit the `please.ini` configuration. 

Or, perhaps any user who's name starts `admin` may execute `useradd` and `userdel`:

```
[admin_users]
name = admin_\S+
permit = true
require_pass = false
rule = /usr/sbin/user(add -m|del) \S+
```

# Files

/etc/please.ini

# Big installs

For big installs, consider the following:

## Consolidate

Where you can use groups when all member least privilege matches the set. It is best here to consider that people often perform the same role, so try and organise the rules that way, so use either a group or list accounts in a single `name` regex match.

## Central configuration considerations

To avoid single points of failure in a service, `ini` configuration should be generated in a single location and pushed to installs. `ini` files parse very quickly whilst accessing LDAP is not only slower but also error prone.

It could be possible to use caching, but a form of positive (correct match) and negative (incorrect match) would be required. 10,000 computers with hundreds of active users performing lookups against an LDAP server could be problematic.

For these reasons I prefer rsync distribution as the protocol is highly efficient and reduces network transfer overall.

LDAP may at a later date be reconsidered.

# Contributions

Should you find anything that you feel is missing, regardless of initial design, please feel free to raise an issue with or without a pull request.

Locating bugs and logging issues are very appreciated, and I thank you in advance.

I welcome pull requests with open arms.

# Locations

The source code for this project is currently hosted on [gitlab](https://gitlab.com/edneville/please) and mirrored to [github](https://github.com/edneville/please). There is a [crate on crates.io](https://crates.io/crates/pleaser). It also has a [homepage](https://www.usenix.org.uk/content/please.html) where other project information is kept.

# Why pleaser in some circles?

This project is named "please". In some places that project name was used by others for other things. Some packages will be named pleaser, some will be named please. The only important thing is if you wish someone to make you a sandwich, just say "please" first.

