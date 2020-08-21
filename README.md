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

Next, configure your /etc/please.conf similar to this, replace user names with appropriate values:

```
user=ed:target=root:permit=true ^/bin/bash
user=ed:target=root:require_pass=true:permit=true ^/bin/bash
user=ed:target=rust:require_pass=false:permit=true ^/bin/\(ba\|da)\?sh
user=ed:target=root:require_pass=false:edit=true:permit=true ^/etc/init.d/
```

The format is as follows, multiple arguments are separated by `:`:

```
[user|target|require_pass|permit|notbefore|notafter]=value regex
```

Using an anchor (`^`) for the regex field will be as good as saying the rule should match any command.

Regex brackets should be escaped: `\(\)`.

```
$ please /bin/bash
#
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

If you wish to give bob access to the `postgres` account for the weekend, the two are the same:

```
user=bob:target=postgres:notbefore=20200808000000:notafter=20200810235959 ^
user=bob:target=postgres:notbefore=20200808:notafter=20200810 ^
```

Many enterprises may wish to permit access to a user for a limited time only, even if that individual is in the role permanently.

# pleaseedit

`pleaseedit` enables editing of files as another user. Enable editing rather than execution with `edit=true`. The first argument will be passed to `EDITOR`.

This is performed as follows:

1. user runs edit as `pleaseedit -u root /etc/fstab`
2. `/etc/fstab` is copied to `/tmp/fstab.pleaseedit.tmp`
3. user's `EDITOR` is executed against `/tmp/fstab.pleaseedit.tmp`
4. if `EDITOR` exits 0 then `/tmp/fstab.pleaseedit.tmp` is copied to `/etc/fstab.pleaseedit.tmp`
5.  `/etc/fstab.pleaseedit.tmp` is set as root owned and `renamed` to `/etc/fstab`

# FILES

/etc/please.conf

# contributions

I welcome pull requests with open arms.

# todo

```
[ ] nested user groups
[ ] read links on source of edits and don't stray outside of permitted rule
[ ] authentication disk caching
[ ] docker image for testing
[ ] plugins/modules
[ ] include readpart .d files
[ ] packages
```

