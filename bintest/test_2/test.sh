#!/bin/sh

set -e

echo "test that when given a reason and search_path='' then echo not found"

# since we can't find an echo then the rules traverse downwards
# consider changing this to ensure that tester has a search_path
# that's different, there's no definition for tester in the config, so the
# message should be just 'echo'

echo '/usr/bin/please -r ree echo worked' | su - tester \
    | grep -E 'You may not execute "echo worked"'


