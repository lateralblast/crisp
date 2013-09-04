rsacheck
--------

A Perl script to check a RSA SecurID PAM Agent installation

Usage
-----

	# rsacheck.pl -[h|V|c]

	-V: Print version information
	-h: Print help
	-c: Check RSA installation
	-I: Create install script with embedded binary
	-i: Install RSA SecurID PAM Agent
	-u: Uninstall RSA SecurID PAM Agent

Example
-------

To create an install script with the tar file packed in it, 
copy the RSA SecurID PAM Agent tar file and your sdconf.rec
file to the directory where the script is.

	$ ls
	PAM-Agent_v7.1.0.149.01_14_13_00_07_15.tar.gz
	stopts.rc
	rsacheck.pl
	README.md

Then run the script:

	$ ./rsacheck.pl -I

	$ ls
	PAM-Agent_v7.1.0.149.01_14_13_00_07_15.tar.gz
	stopts.rc
	rsacheck.pl
	README.md
	rsainstall.pl

This will check to make sure the sdopts.rec file is bundled in the tar,
and then create and install script (rsainstall.pl) with the tar file
packed into the end of the script. This allows it to be easily moved
around for installs.

Once the install script is created it carries with it the RSA SecurID
PAM Agent installer, so to install the client simple run the following
command:

	$ rsainstall.pl -i

To uninstall the agent:

	$ rsainstall -u
