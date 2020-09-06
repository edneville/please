# please, a sudo clone with regex support

Great! This is what I needed.

The aim is to allow admins to delegate accurate least privilege access with ease. There are times when what is intended to be executed can be expressed easily with a regex to expose only what is needed and nothing more.

# how do i install it

A simple install:

```
  git clone https://gitlab.com/edneville/please.git
  cd please
  cargo test && cargo build --release \
  && cp target/release/please target/release/pleaseedit /usr/local/bin \
  && chown root:root /usr/local/bin/please /usr/local/bin/pleaseedit
  && chmod 4755 /usr/local/bin/please /usr/local/bin/pleaseedit
```

# how do i set it up

Next, configure your `/etc/please.ini` similar to this, replace user names with appropriate values. One of the simplest, that does not require password authentication can be defined as follows, assuming the user is `ed`:

```
[ed_root_any]
user=ed
target=root
permit=true
regex = .*
require_pass=false
```

The ini format is as follows, multiple arguments are separated by `:`:

| part           | effect       |
|----------------|--------------|
| [section-name] | section name, naming sections may help you later |
| user=regex     | mandatory, apply configuration to this person |
| target=regex   | mandatory in run and edit, become this user   |
| require_pass=[true/false]   | defaults to true, mandatory in run and edit, become this user   |
| regex=rule     | mandatory, this is the regex for the section |
| notbefore     | the date, in YYYYmmdd or YYYYmmddHHMMSS when this rule becomes effective |
| notafter     | the date, in YYYYmmdd or YYYYmmddHHMMSS when this rule expires |
| list=[true/false] | permit listing of users matching the regex rule |
| edit=[true/false] | permit editing of files matching the regex rule as the target user |

Using a greedy `.*` for the regex field will be as good as saying the rule should match any command. In previous releases there was no anchor (`^` and `$`) however, it seems more sensible to follow `find`'s approach and insist that there are anchors around the regex. This avoids `/bin/bash` matching `/home/user/bin/bash` unless the rule permits something like `/home/%{USER}/bin/bash`.

```
$ please /bin/bash
root#
```

Or to execute as a user other than `root`, such as `postgres`:

```
$ please -t postgres /bin/bash
postgres$
```

The ordering of rules matters. The last match will win. Set `permit=false` if you wish to exclude something, but this should be very rare as the permit should be against a regex rather than using a positive and then a negative match. A rule of best practice is to avoid a fail open and then try and exclude most of the universe.

# dated ranges

For large environments it is not unusual for a third party to require access during a short time frame for debugging. To accommodate this there are the `notbefore` and `notafter` time brackets. These can be either `YYYYMMDD` or `YYYYMMDDHHMMSS`.

The whole day is considered when using the shorter date form of `YYYYMMDD`.

Many enterprises may wish to permit access to a user for a limited time only, even if that individual is in the role permanently.

# pleaseedit

`pleaseedit` enables editing of files as another user. Enable editing rather than execution with `edit=true`. The first argument will be passed to `EDITOR`.

This is performed as follows:

1. user runs edit as `pleaseedit -u root /etc/fstab`
2. `/etc/fstab` is copied to `/tmp/fstab.pleaseedit.tmp`
3. user's `EDITOR` is executed against `/tmp/fstab.pleaseedit.tmp`
4. if `EDITOR` exits 0 then `/tmp/fstab.pleaseedit.tmp` is copied to `/etc/fstab.pleaseedit.tmp`
5.  `/etc/fstab.pleaseedit.tmp` is set as root owned and `renamed` to `/etc/fstab`

# examples

Members of the `audio` group may remove temporary users that an application may not have cleaned up in the form of `username_tmp.<10 random alphanumerics>` using `userdel`:

```
[user_remove_tmp_user]
name = audio
group = true
permit = true
require_pass = false
regex = /usr/sbin/userdel -f -r %{USER}_tmp\.[a-zA-Z0-9]{10}
```

# FILES

/etc/please.ini

# contributions

I welcome pull requests with open arms.

# todo

```
[ ] read links on source of edits and don't stray outside of permitted rule
[ ] docker image for testing
[ ] plugins/modules
[ ] include readpart .d files
[ ] packages
```

