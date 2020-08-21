% PLEASE(1) please user manual
% Ed Neville (ed-please@s5h.net)
% 16 August 2020

# NAME

please.conf

# DESCRIPTION

The `please.conf` file contains the ACL for users of the `please` and `pleaseedit` programs.

All rules in `please.conf` will permit or deny based on command regex matches.

The format is as follows, multiple arguments are separated by `:`:

```
[user|target|require_pass|permit|notbefore|notafter|edit]=value regex
```

`regex` is a regular expression.

Using an anchor (`^`) for the regex field will be as good as saying the rule should match any command.

`notbefore`


# EXAMPLE

User `ed` may only start or stop a docker container:

```
user=ed:target=root:permit=true ^/usr/bin/docker \(start|stop\) \S+
```

User `ben` may only edit `/etc/fstab`:

```
user=ben:target=root:permit=true:edit=true ^/etc/fstab$
```

User joker can do what they want as root on `1st April 2021`:

```
user=joker:target=root:permit=true:notbefore=20210401:notafter=20210401 ^/bin/bash
```

# DATED RANGES

For large environments it is not unusual for a third party to require access during a short time frame for debugging. To accommodate this there are the `notbefore` and `notafter` time brackets. These can be either `YYYYMMDD` or `YYYYMMDDHHMMSS`.

The whole day is considered when using the shorter date form of `YYYYMMDD`.

If you wish to give bob access to the `postgres` account for the weekend, the two are the same:

```
user=bob:target=postgres:notbefore=20200808000000:notafter=20200810235959 ^
user=bob:target=postgres:notbefore=20200808:notafter=20200810 ^
```

Many enterprises may wish to permit access to a user for a limited time only, even if that individual is in the role permanently.

# REGEX NOTES

1. Regex brackets should be escaped: `\(\)`.
2. +, to indicate that a sequence is more than once, does not require escaping.

# FILES

/etc/please.conf

# CONTRIBUTIONS

I welcome pull requests with open arms.

