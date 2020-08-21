% PLEASE(1) please user manual
% Ed Neville (ed-please@s5h.net)
% 16 August 2020

# NAME

please - a tool for access elevation.

# SYNOPSIS

```
please /bin/bash
please -t backup tar -cvf - /home/data | ...
pleaseedit /etc/fstab
please -l
```

# DESCRIPTION

please is a sudo clone that has regex support and a simple approach to ACL.

The aim is to allow admins to delegate accurate least privilege access with ease. There are times when what is intended to be executed can be expressed easily with a regex to expose only what is needed and nothing more.

# EXAMPLES

Run a shell as the httpd user:

```
please -t httpd /bin/bash
```

# FILES

/etc/please.conf

# CONTRIBUTIONS

I welcome pull requests with open arms.

# SEE ALSO

please.conf


