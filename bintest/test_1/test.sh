#!/bin/sh

# test first that /bin/echo is found in the section with no search path

set -e

echo '/usr/bin/please -r ree /bin/echo worked' | su - ed | grep -Fx worked

# test that we fall back into the section in please.ini that has a default
# search path
echo '/usr/bin/please -r ree echo worked | grep -Fx "Cannot read password without tty"' | su - ed

