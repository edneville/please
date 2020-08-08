# please, a sudo clone with regex support

Great! This is what I needed.

The aim is to allow admins to delegate accurate least privilege access with ease. There are times when what is intended to be executed can be expressed easily with a regex to expose only what is needed and nothing more.

# how do i use it

Firstly, configure your /etc/please.conf similar to this, replace user names with appropriate values:

```
user=ed:target=root:permit=true ^/bin/bash
user=ed:target=root:require_pass=true:permit=true ^/bin/bash
user=ed:target=rust:require_pass=false:permit=true ^/bin/bash
```

The format is as follows, multiple arguments are separated by `:`:

```
[user|target|require_pass|permit|notbefore|notafter]=value regex
```

# dated ranges

For large environments it is not unusual for a third party to require access during a short time frame for debugging. To accommodate this there are the `notbefore` and `notafter` time brackets. These can be either `YYYYMMDD` or `YYYYMMDDHHMMSS`.

The whole day is considered when using the shorter date form of `YYYYMMDD`.

If you wish to give bob access to the `postgres` account for the weekend, the two are the same:

user=bob:target=postgres:notbefore=20200808000000:notafter=20200810235959 ^
user=bob:target=postgres:notbefore=20200808:notafter=20200810 ^

Many enterprises may wish to permit access to a user for a limited time only, even if that individual is in the role permanently.

# todo

[ ] groups
[ ] plugins
[ ] man page
[ ] authentication disk caching
[ ] packages
[ ] docker image for testing

