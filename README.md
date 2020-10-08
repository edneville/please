# Please, a sudo clone with regex support

Great! This is what I needed.

The aim is to allow admins to delegate accurate least privilege access with ease. There are times when what is intended to be executed can be expressed easily with a regex to expose only what is needed and nothing more.

# How do I install it

A simple install:

```
  git clone https://gitlab.com/edneville/please.git
  cd please
  cargo test && cargo build --release \
  && cp target/release/please target/release/pleaseedit /usr/local/bin \
  && chown root:root /usr/local/bin/please /usr/local/bin/pleaseedit
  && chmod 4755 /usr/local/bin/please /usr/local/bin/pleaseedit
```

Optionally, set `sudo` as an alias of `please`:

```
alias sudo="please"
alias sudoedit="pleaseedit"
```

# How do I set it up

Next, configure your `/etc/please.ini` similar to this, replace user names with appropriate values. One of the simplest, that does not require password authentication can be defined as follows, assuming the user is `ed`:

The options are as follows:

| part                        | effect       |
|-----------------------------|--------------|
| [section-name]              | Section name, naming sections may help you later. |
| name=regex                  | Mandatory, apply configuration to this entity. |
| target=regex                | May become these users. |
| permit=[true/false]         | Defaults to true |
| require_pass=[true/false]   | Defaults to true, mandatory in run and edit, become this user.   |
| regex=rule                  | This is the regex for the section, default is ^$ |
| notbefore                   | The date, in YYYYmmdd or YYYYmmddHHMMSS when this rule becomes effective. |
| notafter                    | The date, in YYYYmmdd or YYYYmmddHHMMSS when this rule expires. |
| datematch=[Day Mon dd HH:MM:SS UTC YYYY] | regex to match against a date string |
| type=[edit/run/list]        | Set the entry type. Run = execution, edit = pleaseedit, list = show user rights |
| group=[true/false]          | True to signify that name= refers to a group rather than a user. |
| hostname=regex              | Hosts where this applies. Defaults to 'localhost'. |
| dir=regex                   | Permit switching to regex defined directory prior to execution. |
| include=file                | Include file as another ini source, other options will be skipped in this section. |
| includedir=dir              | Include dir of `.ini` files as other sources, in ascii sort order other options will be skipped in this section. Files not matching `.ini` will be ignored to allow for editor tmp files. |
| editcmd=[program]           | (edit) continue with file replacement if `program` exits 0 |
| editmode=[octal mode]       | (edit) set destination file mode to `octal mode` |

`include` and `includedir` will override mandatory arguments.

Using a greedy `.*` for the regex field will be as good as saying the rule should match any command. In previous releases there was no anchor (`^` and `$`) however, it seems more sensible to follow `find`'s approach and insist that there are anchors around the regex. This avoids `/bin/bash` matching `/home/user/bin/bash` unless the rule permits something like `/home/%{USER}/bin/bash`.

If a `include` directive is met, no other enties in the section will be processed. The same goes for `includedir`.

The ordering of rules matters. The last match will win. Set `permit=false` if you wish to exclude something, but this should be very rare as the permit should be against a regex rather than using a positive and then a negative match. A rule of best practice is to avoid a fail open and then try and exclude most of the universe.

For example, using the two entries below:

```
[ed_root_du]
name=ed
target=root
permit=true
regex = ^(/usr)?/bin/du\s.*
require_pass=false
```

```
[ed_postgres]
name=ed
target=postgres
permit=true
regex = /bin/bash
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

Another date type is the `datematch` item, this constrains sections to a regex match against the date string `Day Mon HH:MM:SS UTC Year`.

You can permit some a group of users to perform some house keeping on a Monday:

```
[l2_housekeeping]
name=l2users
group=true
target=root
permit=true
regex = /usr/local/housekeeping/.*
datematch = ^Mon.*
```

# pleaseedit

`pleaseedit` enables editing of files as another user. Enable editing rather than execution with `edit=true`. The first argument will be passed to `EDITOR`.

This is performed as follows:

1. user runs edit as `pleaseedit -u root /etc/fstab`
2. `/etc/fstab` is copied to `/tmp/fstab.pleaseedit.$USER`
3. user's `EDITOR` is executed against `/tmp/fstab.pleaseedit.$USER`
4. if `EDITOR` exits 0, and `editcmd` exits 0, then `/tmp/fstab.pleaseedit.$USER` is copied to `/etc/fstab.pleaseedit.$USER`
5.  `/etc/fstab.pleaseedit.$USER` is set as root owned and `renamed` to `/etc/fstab`

# editcmd

editcmd can be used prior to the tmp edit file move to the source location. This can be used to test configuration files are valid prior to renaming in place.

For something similar to apache, consider copying the config tree to a tmp directory before running the test to accommodate includes.

# Other examples

Members of the `audio` group may remove temporary users that an application may not have cleaned up in the form of `username_tmp.<10 random alphanumerics>` using `userdel`:

```
[user_remove_tmp_user]
name = audio
group = true
permit = true
require_pass = false
regex = /usr/sbin/userdel -f -r %{USER}_tmp\.[a-zA-Z0-9]{10}
```

How about, for the purpose of housekeeping, some users may be permitted to destroy zfs snapshots that look roughly like they're date stamped:

```
[user_remove_snapshots]
name = data
group = true
permit = true
require_pass = false
regex = /usr/sbin/zfs destroy storage/photos@\d{8}T\d{6}
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
regex = /usr/sbin/user(add|del)\s.*
```

# Files

/etc/please.ini

# Contributions

I welcome pull requests with open arms.

# Locations

The source code for this project is currently hosted on [gitlab](https://gitlab.com/edneville/please) and mirrored to [github](https://github.com/edneville/please). There is a [crate on crates.io](https://crates.io/crates/pleaser). It also has a [homepage](https://www.usenix.org.uk/content/please.html) where other project information is kept.

# Why pleaser in some circles?

This project is named "please". In some places that project name was used by others for other things. Some packages will be named pleaser, some will be named please. The only important thing is if you wish someone to make you a sandwich, just say "please" first.

# Todo

```
[ ] read links on source of edits and don't stray outside of permitted rule
[ ] docker image for testing
[ ] plugins/modules
[ ] packages
```

