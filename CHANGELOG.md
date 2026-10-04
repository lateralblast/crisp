# Changelog

All notable changes to this project are documented in this file.

## [0.5.0] - 2026-10-04
- Added exit status codes, usage on invalid options, executable install script, and guards for missing sudo and /tmp/sdconf.rec

## [0.4.9] - 2026-10-04
- Moved option handling into main(), removed unused variables, added explicit returns and fixed comment typos

## [0.4.8] - 2026-10-04
- Replaced uname and hostname shell commands with POSIX and Sys::Hostname

## [0.4.7] - 2026-10-04
- Run gzip, tar and the vendor install and uninstall scripts without a shell, with quoting for the remaining pipelines

## [0.4.6] - 2026-10-04
- Added read_file and write_file helpers using lexical filehandles and three argument open with error reporting

## [0.4.5] - 2026-10-04
- Replaced touch, mkdir, cp, rm, chmod, chown and chgrp shell commands with Perl built-ins and core modules

## [0.4.4] - 2026-10-04
- Replaced cat/grep/head/sed/strings shell pipelines with Perl file reads and writes

## [0.4.3] - 2026-10-04
- Read script version in Perl instead of a cat/grep/awk shell pipeline

## [0.4.2] - 2026-10-04
- Enabled warnings and made get_sudoers and get_sudo_bin return an empty string when not found

## [0.4.1] - 2026-10-04
- Updated documentation for -f option

## [0.4.0] - 2026-10-04
- Fixed IP address determination when hostname has no entry in /etc/hosts

## [0.3.9] - 2026-10-04
- Get OS name in uninstall mode so the correct PAM file is restored

## [0.3.8] - 2026-10-04
- Fixed name of the created install script header (was rsainstall.pl.pl)

## [0.3.7] - 2026-10-04
- Fixed array element access to use scalar syntax

## [0.3.6] - 2026-10-04
- Replaced here docs with space indented terminators with printf pipes for install and uninstall

## [0.3.5] - 2026-10-04
- Fixed duplicate declaration of $ace_status which broke the 32 bit acestatus fallback

## [0.3.4] - 2026-10-04
- Fixed typo in touch command

## [0.3.3] - 2026-10-04
- Fixed missing parameter message in sd_pam.conf check to name the parameter

## [0.3.2] - 2026-10-04
- Fixed inverted sd_pam.conf value check, line rewrite and blank lines added when updating it

## [0.3.1] - 2026-10-04
- Fixed ownership and group checks comparing names with numeric operator

## [0.3.0] - 2026-10-04
- Fixed typo in file handle name (OUPUT) when updating PAM file

## [0.2.9] - 2026-10-04
- Removed exit that stopped uninstall after restoring PAM file

## [0.2.8] - 2026-10-04
- Removed stray exit that stopped pam.conf/pam.d sudo fix from being applied

## [0.2.7] - 2026-10-04
- Close extracted archive file before decompressing it

## [0.2.6] - 2026-10-04
- Fixed '= ~' typos (should be '=~') which overwrote variables instead of matching them

## [0.2.5] - 2014-06-17
- Updated documentation and license

## [0.2.4] - 2013-09-19
- Bug fix

## [0.2.3] - 2013-09-10
- Fixed more bugs with IP Address determination

## [0.2.2] - 2013-09-10
- Fixed IP Address discovery on Linux

## [0.2.1] - 2013-09-09
- Improved determination of IP

## [0.2.0] - 2013-09-09
- Fixed creation of /var/ace/sdopts.rec

## [0.1.9] - 2013-09-09
- Updated documentation

## [0.1.8] - 2013-09-09
- Improved user feedback messages

## [0.1.7] - 2013-09-06
- Improved installation and uninstallation

## [0.1.6] - 2013-09-06
- Fixed etc directory for CSWsudo package

## [0.1.5] - 2013-09-06
- Improved install script creation

## [0.1.4] - 2013-09-05
- Added code to create installer with packed tar file

## [0.1.3] - 2013-09-04
- Added code to update pam.conf and sd_pam.conf

## [0.1.2] - 2013-09-04
- Added code to fix things

## [0.1.1] - 2013-09-04
- Added code to create installer script

## [0.1.0] - 2013-09-04
- Added initial install code

## [0.0.9] - 2013-08-26
- Fixed permissions check to include directories

## [0.0.8] - 2013-08-26
- Added file and group permissions check

## [0.0.7] - 2013-08-25
- Code clean up

## [0.0.6] - 2013-08-25
- Fixed sd_pam.conf hash

## [0.0.5] - 2013-08-17
- Cleaned up code

## [0.0.4] - 2013-08-17
- Used hashes for parameters and values in /etc/sd_pam.conf

## [0.0.3] - 2013-08-16
- Removed -m switch

## [0.0.2] - 2013 (date not recorded)
- Linux support

## [0.0.1] - 2013-08-12
- Initial version
