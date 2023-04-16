0.5.5

* and_hms -> and_hms_opt
* macos beta support
* optionally resume when pleasedit exitcmd fails

0.5.4

* check mode can run when the please binary is not setuid (github#4)
* improve documentation around default sections
* add search_path to search directories for binary
* add token_timeout to configure token expiration
* zsh tab completion from @Mynacol (gitlab!62)
* bash tab completion (experimental)
* bump regex to 1.7, nix to 0.25, rpassword to 6.0 (dkg)

0.5.3

* [fix] require_pass handling spotted by voidpin

0.5.2

* do not read config files that have already been processed
* permit reason (-r) strings as regex matches
* %{HOSTNAME} expands to hostname in regex rules
* suggest -d when invoked with cd and cd is not located
* new option of timeout for password prompt
* new option of target_group for run/edit

0.5.1

* editmode=keep now default if no other mode is specified
* only include files in includedir if they do not start with .
* trimmed error when unable to communicate with syslog

0.5.0

* backslashes within arguments now require escaping
* editmode=keep to preserve the file permission bits from an existing file
* exact_{rule,target,name,hostname,dir} which are literal
* nix bump to 0.23.0
* deprecating regex term in favour of rule

0.4.2

* allow environments to pass through
* allow some environment variables to be forced
* handle tstp from shell to editor

0.4.1

* condensing clock and fixing for 32bit
* merging syslog version dependency
* pam conversation separation for netbsd

0.4.0

* Changing chmod in pleaseedit to use fd
* splitting do_environment into set and clean
* umask into set_environment
* renaming reset and eprivs to esc and drop
* fchown on fd
* search_path and do_dir_changes print os errors
* use seteuid/setguid
* use nofollow
* dir should be limited to range, or excluded if not specified
* use rand characters in temp file names
* limit config processing to 10MB
* valid token uses both wall and monotonic clock
* pam follows conversation
* failed edits are now cleaned upon editor exit

Thanks to Matthias Gerstner for these recommendations

0.3.22

* [fix] spaces within arguments should be escaped
* -u should alias -t
* please and pleaseedit should output help when run without arguments

0.3.21

Cargo.lock for packagers

* [fix] don't output unparsed config
* [fix] path enumeration reported by @noproto
* man page tidy
* list error should show "your"

0.3.20

* Add current working directory to the syslo
* Fix editor execution if it has arguments

0.3.19

* [fix] group list in pleaseedit

0.3.18

* New syslog bool
* exitcmd placeholders

0.3.17

* Man improvements

0.3.16

* Minor optimisations
* documentation around repeating regex rules

0.3.15

* Performance improvements

0.3.14

* 'last' option to halt processing on match

0.3.13

* documentation fix for datematch

0.3.12

* setgroup error capture

0.3.11

* crate dependency change to align with debian

