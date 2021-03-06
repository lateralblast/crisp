#!/usr/bin/env perl

# Name:         crisp.pl
# Version:      0.2.5
# Release:      1
# License:      CC-BA (Creative Commons By Attrbution)
#               http://creativecommons.org/licenses/by/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          N/A
# Distribution: Solaris / Linux
# Vendor:       Lateral Blast
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Script to check RSA SecurID PAM Agent is installed correctly

use strict;
use Getopt::Std;
use File::Basename;

my $script_name    = $0;
my $work_dir       = ".";
my $start_script   = basename($script_name);
my $install_script = "rsainstall.pl";
my $script_version = `cat $script_name | grep '^# Version' |awk '{print \$3}'`;
my $options        = "IVcfhiu";
my @bin_dirs       = (
  "/usr/local/bin" , "/usr/local/sbin",
  "/opt/csw/bin"   , "/opt/csw/sbin",
  "/usr/sfw/bin"   , "/usr/sfw/sbin",
  "/usr/bin"       , "/usr/sbin"
);
my @etc_dirs       = (
  "/usr/local/etc" , "/etc/opt/csw",
  "/usr/sfw/etc"   , "/etc"
);
my %option         = ();
my $host_name;
my $host_ip;
my $admin_group    = "sysadmin";
my $uc_admin_group = uc($admin_group);
my $os_name;
my %sd_pam_vals    = (
  "ENABLE_GROUP_SUPPORT" , "1",
  "INCL_EXCL_GROUPS"     , "1",
  "LIST_OF_GROUPS"       , "$admin_group"
);
my $rsa_version = "7.1.0.149.01_14_13_00_07_15";
my $tmp_dir     = "/tmp";
my $pam_dir     = "/opt/pam";
my $ace_dir     = "/var/ace";
my $sdopts_file = "$ace_dir/sdopts.rec";
my $sdconf_file = "$ace_dir/sdconf.rec";
my $pam_name    = "PAM-Agent_v".$rsa_version;
my $ins_dir     = "$tmp_dir/$pam_name";

if ($#ARGV == -1) {
  print_usage();
}
else {
  getopts($options,\%option);
}

# If given -h print usage

if ($option{'h'}) {
  print_usage();
  exit;
}

sub print_version {
  print "$script_version";
  return;
}

# Print script version

if ($option{'V'}) {
  print_version();
  exit;
}

# Run check

if ($option{'c'}) {
  get_host_info();
  print "Hostname is $host_name\n";
  print "IP Address is $host_ip\n";
  rsa_check();
  exit;
}

# If running in install mode, set the fix flag to 1

if ($option{'i'}) {
  $option{'f'} = 1;
  get_host_info();
  extract_file();
  install_rsa();
  rsa_check();
  exit;
}

# If given -u uninstall

if ($option{'u'}) {
  uninstall_rsa();
  exit;
}

# If give -I create installer script

if ($option{'I'}) {
  create_install_script();
  exit;
}

# Subroutine to print usage

sub print_usage {
  print "\n";
  print "Usage: $script_name -$options\n";
  print "\n";
  print "-V: Print version information\n";
  print "-h: Print help\n";
  print "-c: Check RSA installation\n";
  print "-f: Fix RSA installation\n";
  print "-I: Create install script with embedded binary\n";
  print "-i: Install RSA SecurID PAM Agent\n";
  print "-u: Uninstall RSA SecurID PAM Agent\n";
  print "\n";
  return;
}

# Subroutine to get host information

sub get_host_info {
  my @fqhn;
  $os_name = `uname`;
  chomp($os_name);
  $host_name = `hostname`;
  if ($host_name = ~/\./) {
    @fqhn      = split(/\./,$host_name);
    $host_name = @fqhn[0];
  }
  chomp($host_name);
  $host_ip = `cat /etc/hosts |grep -v localhost |awk '{print \$1" "\$2}' |grep '$host_name'`;
  ($host_ip,$host_name) = split(/\s+/,$host_ip);
  if ($host_ip!~/\./) {
    $host_ip = `cat /etc/hosts |grep -v localhost |awk '{print \$1" "\$3}' |grep '$host_name'`;
  }
  ($host_ip,$host_name) = split(/\s+/,$host_ip);
  chomp($host_ip);
  return;
}

# Subroutine to create installer script
# This creates a copy of the script and embeds the tar.gz to the end of it

sub create_install_script {
  my $tar_file   = "$work_dir/$pam_name".".tar";
  my $gz_file    = "$tar_file".".gz";
  my $key_check;
  my $check_file = "sdconf.rec";
  # Check the the PAM Agent .tar.gz file exists
  # If the gz file doesn't exist but the tar does, gzip the tar
  if (!-e "$gz_file") {
    if ( -e "$tar_file") {
      system("gzip $tar_file");
    }
    else {
      print "Copy $tar_file (or gzipped version) into current directory and re-run script\n";
      exit;
    }
  }
  # Check that we are not running the created script
  if ($script_name = ~/$install_script/) {
    print "You should be running the original script not the packed script!\n";
    exit;
  }
  # Check whether the server config file (stdconf.rec) is in the .tar.gz
  # This file is required for the install
  $key_check = `gzip -dc $gz_file |tar -tf - |grep $check_file`;
  if ($key_check!~/$check_file/) {
    if (! -e "$check_file") {
      print "Copy $check_file into current directory and re-run script\n";
      exit;
    }
    # If the file is not in the archive, then add it for the current directory
    print "File $check_file not in archive\n";
    print "Adding $check_file to archive\n";
    system("gzip -d $gz_file");
    system("tar -rf $tar_file $check_file");
    system("gzip $tar_file");
  }
  # Copy the script and embed the .tar.gz at the end
  system("cat $script_name | sed 's/# Name:         $start_script/# Name:         $install_script.pl/g'> $work_dir/$install_script");
  system("cat $gz_file >> $work_dir/$install_script");
  return;
}

# Subroutine to extract the .tar.gz from the install script

sub extract_file {
  my $tar_file = "$tmp_dir/$pam_name".".tar";
  my $gz_file  = "$tar_file".".gz";
  # Check to see it hasn't already been extracted
  # Useful for testing purposes to not have to extract every time
  # In this case disable the clean up subroutine
  if (! -e "$ins_dir") {
    # Extract the .tar.gz from the script
    if (! -e "$gz_file") {
      open(OUTFILE,">","$gz_file");
      while (<DATA>) {
        print OUTFILE $_;
      }
    }
    # Extract the .tar for the .tar.gz
    if (! -e "$tar_file") {
      if (-e "$gz_file") {
        system("cd $tmp_dir ; gzip -d $gz_file");
      }
    }
    # Untar the tar file and fix the installer script to ignore the license message
    if ( -e "$tar_file") {
      system("cd $tmp_dir ; tar -xpf $tar_file");
      system("cd $ins_dir ; cat install_pam.sh |sed 's/^startup_screen\$/#&/g' > install_pam.sh.new");
      system("cd $ins_dir ; cat install_pam.sh.new > install_pam.sh");
    }
  }
  # Check /var/ace
  if (-e "$ins_dir") {
    var_ace_check();
  }
  else {
    print "Directory $ins_dir does not exist\n";
  }
  return;
}

# Subroutine to run the uninstall script
# Uses a here doc to answer the questions

sub uninstall_rsa {
  my $sudoers = get_sudoers();
  if (-e "$pam_dir") {
    system("$pam_dir/uninstall_pam.sh <<-UNINSTALL

      y
      y
      y
      UNINSTALL");
  }
  sudo_passwd_check($sudoers);
  pam_sudo_check();
}

# Subroutine to run the install script
# Uses a here doc to answer the questions

sub install_rsa {
  if (-e "$ins_dir") {
    system("$ins_dir/install_pam.sh <<-INSTALL



      INSTALL");
  }
  install_clean_up();
}

# Subroutine to check that sudo is compiled with PAM support

sub sudo_pam_check {
  my $sudo_bin  = $_[0];
  my $sudo_pam  = `strings $sudo_bin |grep pam`;
  if ($sudo_pam = ~/with\-pam|libpam/) {
    print "Sudo has PAM support\n";
  }
  else {
    print "Warning: Sudo does not have PAM support\n";
  }
}

# Subroutine to check a file exists

sub check_file_exists {
  my $file_name = $_[0];
  if ($option{'f'}) {
    if (! -e "$file_name") {
      system("tocuh $file_name");
    }
  }
  if (! -e "$file_name") {
    print "Warning: File $file_name does not exist\n";
    return("");
  }
  else {
    print "File $file_name exists\n";
    return($file_name);
  }
}

# Subrouting to check a directory exists

sub check_dir_exists {
  my $dir_name = $_[0];
  if ($option{'f'}) {
    if (! -d "$dir_name") {
      system("mkdir -p $dir_name");
    }
  }
  if (! -d "$dir_name") {
    print "Warning: Directory $dir_name does not exist\n";
    return("");
  }
  else {
    print "Directory $dir_name exists\n";
    return($dir_name);
  }
}

# Subroutine to run acestatus

sub ace_status_check {
  my $ace_status = "$pam_dir/bin/64bit/acestatus";
  my $ace_status = check_file_exists($ace_status);
  my @ace_output;
  my $line;
  if (! -e "$ace_status") {
    $ace_status = ~s/64/32/g;
    $ace_status = check_file_exists($ace_status);
  }
  if (-e "$ace_status") {
    @ace_output = `$ace_status 2>&1`;
    foreach $line (@ace_output) {
      chomp($line);
      print "$line\n";
    }
  }
}

# Subroutine to check entries in /etc/sd_pam.conf

sub sd_pam_check {
  my $sd_pam_file = "/etc/sd_pam.conf";
  my @file_info;
  my $line;
  my $key;
  my $hash_param;
  my $hash_value;
  my $line_param;
  my $line_value;
  my %results;
  my $counter;
  my $change = 0;
  $sd_pam_file = check_file_exists($sd_pam_file);
  while (($hash_param,$hash_value) = each(%sd_pam_vals)) {
    $results{$hash_param} = 0;
  }
  if (-e "$sd_pam_file") {
    @file_info = `cat $sd_pam_file`;
    for ($counter = 0; $counter<@file_info; $counter++) {
      $line = @file_info[$counter];
      chomp($line);
      while (($hash_param,$hash_value) = each(%sd_pam_vals)) {
        if ($line = ~/^$hash_param/) {
          $results{$hash_param} = 1;
          ($line_param,$line_value) = split(" = ",$line);
          if ($line_value!~/^$hash_value/) {
            print "Parameter $hash_param correctly set to $hash_value\n";
          }
          else {
            $change = 1;
            if ($option{'f'}) {
              if (!-e "$sd_pam_file.prersa") {
                system("cp $sd_pam_file $sd_pam_file.prersa");
              }
              $line = ~s/$line_value/$hash_value/;
              @file_info[$counter] = $line;
            }
          }
        }
      }
    }
    if (!$option{'f'}) {
      while (($hash_param,$hash_value) = each(%results)) {
        if ($hash_value  ==  0) {
          print "File $sd_pam_file does not contain $hash_value\n";
        }
      }
    }
    else {
      if ($change eq 1) {
        open (OUTPUT,">",$sd_pam_file);
        foreach $line (@file_info) {
          print OUTPUT "$line\n";
        }
        close (OUTPUT);
      }
    }
  }
}

# Subroutine to check file permissions

sub check_file_perms {
  my $check_file  = $_[0];
  my $check_user  = $_[1];
  my $check_group = $_[2];
  my $check_perm  = $_[3];
  my $file_mode;
  my $file_user;
  my $file_group;
  if ((-e "$check_file")||(-d "$check_file")) {
    $file_mode  = (stat($check_file))[2];
    $file_mode  = sprintf("%04o",$file_mode & 07777);
    $file_user  = (stat($check_file))[4];
    $file_group = (stat($check_file))[5];
    $file_user  = getpwuid($file_user);
    if ($file_mode != $check_perm) {
      print "Warning: Permissions nf $check_file are not $check_perm\n";
      if ($option{'f'}) {
        print "Fixing permissions on $check_file\n";
        system("chmod $check_perm $check_file");
      }
    }
    else {
      print "Permissions on $check_file are correctly set to $check_perm\n";
    }
    if ($file_user != $check_user) {
      print "Warning: Ownership of $check_file is not $check_user\n";
      if ($option{'f'}) {
        print "Fixing ownership of $check_file\n";
        system("chown $check_user $check_file");
      }
    }
    else {
      print "Ownership of $check_file is correctly set to $check_user\n";
    }
    if ($file_group != $check_group) {
      print "Warning: Group ownership of $check_file is not $check_group\n";
      if ($option{'f'}) {
        print "Fixing group ownership of $check_file\n";
        system("chgrp $check_group $check_file");
      }
    }
    else {
      print "Group ownership of $check_file is correctly set to $check_group\n";
    }
  }
  return;
}

# Subroutine to check /var/ace/sdopts.rec
# Creates it if run in fix mode

sub check_sdopts {
  my $file_info;
  my $sdopts_line = "CLIENT_IP = $host_ip";
  if ($option{'f'}) {
    if (! -e "$sdopts_file") {
      system("touch $sdopts_file");
    }
  }
  check_file_perms($ace_dir,"root","root","750");
  if (-e "$sdopts_file") {
    $file_info = `cat $sdopts_file |head -1`;
    print "File $sdopts_file contains:\n";
    print "$file_info\n";
    if ($file_info!~/$host_ip/) {
      print "File $sdopts_file contains incorrect IP\n";
      print "Entry should be: $sdopts_line\n";
      if ($option{'f'}) {
        print "Fixing $sdopts_file\n";
        open(OUTPUT,">",$sdopts_file);
        print OUTPUT "$sdopts_line\n";
        close(OUTPUT)
      }
    }
    else {
      print "File $sdopts_file contains correct IP\n";
    }
  }
  else {
    if ($option{'f'}) {
      print "Fixing $sdopts_file\n";
      open(OUTPUT,">",$sdopts_file);
      print OUTPUT "$sdopts_line\n";
      close(OUTPUT)
    }
  }
  return;
}

# Subroutine to check that /var/ace exists
# and the correct files and permissions are in place

sub var_ace_check {
  my $tmp_file = "/tmp/sdconf.rec";
  $ace_dir = check_dir_exists($ace_dir);
  # If running installer copy the sdconf.rec file into place
  if ($option{'f'}) {
    if (!-e "$sdconf_file") {
      system("cp $tmp_file $sdconf_file");
      system("rm $tmp_file");
    }
  }
  check_file_perms($sdconf_file,"root","root","640");
  check_file_perms($sdopts_file,"root","root","640");
  check_sdopts();
  return;
}

# Subroutine to check that sudo directive for RSA is in PAM config file

sub pam_sudo_check {
  my $pam_file;
  my $tmp_file = "/tmp/pam.sudo";
  my $pam_check;
  my @file_info;
  my $line;
  if ($os_name = ~/Linux/) {
    $pam_file = "/etc/pam.d/sudo";
  }
  else {
    $pam_file = "/etc/pam.conf";
  }
  if ($option{'u'}) {
    if (-e "$pam_file.prersa") {
      print "Restoring $pam_file\n";
      system("cat $pam_file.prersa > $pam_file");
      system("rm $pam_file.prersa");
      exit;
    }
  }
  else {
    if (-e "$pam_file") {
      $pam_check = `cat $pam_file |grep securid |grep -v '^#'`;
      if ($pam_check = ~/securid/) {
        print "RSA SecurID PAM Agent enabled\n";
        print "File $pam_file contains:\n";
        print "$pam_check\n";
      }
      else {
        print "File $pam_file does not contain securid\n";
        if ($option{'f'}) {
          print "Fixing $pam_file\n";
          system("cp $pam_file $pam_file.prersa");
          exit;
          if ($os_name = ~/Linux/) {
            system("cat $pam_file |sed 's/^auth/#\&/' > $tmp_file");
            system("cat $tmp_file > $pam_file");
            system("rm $tmp_file");
          }
          open(OUTPUT,">>",$pam_file);
          if ($os_name = ~/Linux/) {
            print OUTPUT "auth\trequired\tpam_securid.so reserve\n";
          }
          else {
            print OUTPUT "sudo\tauth\trequired\tpam_securid.so reserve\n";
          }
          close(OUPUT);
        }
      }
    }
  }
  return;
}

# Subroutine to check if /opt/pam exists

sub opt_pam_check {
  $pam_dir = check_dir_exists($pam_dir);
  return;
}

# Subroutine to check that we have a sudoers group entry that points to /etc/group

sub sudo_group_check {
  my $sudoers = $_[0];
  my $group_check;
  if (-e "$sudoers") {
    $group_check = `cat $sudoers |grep '\%$admin_group' |grep -v '^#'`;
    if ($group_check!~/$admin_group/) {
      print "File $sudoers does not contain a \%$admin_group entry\n";
      $group_check = `cat $sudoers |grep $uc_admin_group |grep -v '^#'`;
      if ($group_check = ~/$uc_admin_group/) {
        print "File $sudoers contains and old style $uc_admin_group group which should be migrated to \%$admin_group\n";
      }
    }
    else {
      print "File $sudoers contains a \%$admin_group entry\n";
      print "$group_check\n";
    }
  }
  return;
}

# Subroutine to check that sudoers file requires a password
# to escalate privileges (ie no NOPASSWD entry)

sub sudo_passwd_check {
  my $sudoers = $_[0];
  my $sudotmp = "/tmp/sudoers";
  my $passwd_check;
  if ($option{'u'}) {
    if (-e "$sudoers.prersa") {
      print "Restoring $sudoers\n";
      system("cat $sudoers.prersa > $sudoers");
      system("rm $sudoers.prersa");
    }
  }
  else {
    if (-e "$sudoers") {
      $passwd_check = `cat $sudoers |grep '\%$admin_group' |grep 'NOPASSWD' |grep -v '^#'`;
      if ($passwd_check = ~/NOPASSWD/) {
        print "File $sudoers contains a NOPASSWD entry\n";
        # If running in fix mode take a copt of sudoers and fix NOPASSWD
        if ($option{'f'}) {
          print "Fixing $sudoers\n";
          if (! -e "$sudoers.prersa") {
            system("cp -p $sudoers $sudoers.prersa");
          }
          system("cat $sudoers |sed 's/NOPASSWD/PASSWD/g' > $sudotmp");
          system("cat $sudotmp > $sudoers");
          system("rm $sudotmp");
        }
      }
    }
    else {
      print "File $sudoers requires a password to escalate privileges\n";
    }
  }
  return;
}

# Subroutine to check /etc/group has a entry for the admin/wheel group

sub etc_group_check {
  my $sudoers;
  my $groupfile   = "/etc/group";
  my $group_check = `cat $groupfile |grep '^$admin_group'`;
  if ($group_check!~/$admin_group/) {
    print "File $groupfile does not contain a $admin_group group entry\n";
  }
  else {
    $group_check = `cat $groupfile |grep '^$admin_group' |cut -f4 -d:`;
    if ($group_check!~/[A-z]/) {
      print "File $groupfile has no members in $admin_group\n";
    }
    else {
      print "File $groupfile contains a $admin_group group with members\n";
      if ($option{'f'}) {
        $sudoers = get_sudoers();
        sudo_passwd_check($sudoers);
      }
    }
  }
}

# Main subroutine

sub rsa_check {
  my $sudo_bin = get_sudo_bin();
  my $sudoers  = get_sudoers();
  sudo_pam_check($sudo_bin);
  sudo_group_check($sudoers);
  etc_group_check();
  if (!$option{'i'}) {
    sudo_passwd_check($sudoers);
    var_ace_check();
  }
  opt_pam_check();
  pam_sudo_check();
  sd_pam_check();
  ace_status_check();
  return;
}

# Subroutine to find location of sudoers
# This is reauired as different Solaris packages install n different places

sub get_sudoers {
  my $etc_dir;
  my $sudoetc;
  my @file_info;
  my $line;
  foreach $etc_dir (@etc_dirs) {
    $sudoetc = "$etc_dir/sudoers";
    if (-e "$sudoetc") {
      if ($option{'c'}) {
        print "Sudoers file found at $sudoetc\n";
      }
      return($sudoetc);
    }
  }
}

# Subroutine to find location of sudo
# This is reauired as different Solaris packages install n different places

sub get_sudo_bin {
  my $bin_dir;
  my $sudo_bin;
  my @file_info;
  foreach $bin_dir (@bin_dirs) {
    $sudo_bin = "$bin_dir/sudo";
    if (-e "$sudo_bin") {
      if ($option{'c'}) {
        print "Sudo found at $sudo_bin\n";
      }
      return($sudo_bin);
    }
  }
}

# Subroutine to clean up

sub install_clean_up {
  system("rm -rf /tmp/PAM*");
}

# .tar.gz gets embedded after this

__DATA__
