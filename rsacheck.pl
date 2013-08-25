#!/usr/bin/env perl

use strict;
use Getopt::Std;

# Name:         rsacheck.pl
# Version:      0.0.8
# Release:      1
# License:      Open Source 
# Group:        System
# Source:       N/A 
# URL:          N/A
# Distribution: Solaris / Linux
# Vendor:       Lateral Blast 
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Script to check RSA SecurID PAM Agent is installed correctly

# Changes       0.0.1 Mon Aug 12 08:41:26 EST 2013
#               Initial version
#               0.0.2 
#               Linux support
#               0.0.3 Fri 16 Aug 2013 17:34:43 EST
#               Removed -m switch 
#               0.0.4 Sat 17 Aug 2013 08:50:25 EST
#               Used hashes for parameters and values in /etc/sd_pam.conf
#               0.0.5 Sat 17 Aug 2013 11:11:23 EST
#               Cleaned up code
#               0.0.6 Sun 25 Aug 2013 17:02:53 EST
#               Fixed sd_pam.conf hash
#               0.0.7 Sun 25 Aug 2013 17:21:52 EST
#               Code clean up
#               0.0.8 Mon 26 Aug 2013 08:11:16 EST
#               Added file and group permissions check

my $script_name=$0;
my $script_version=`cat $script_name | grep '^# Version' |awk '{print \$3}'`; 
my $options="Vch";
my @bindirs=( 
  "/usr/local/bin","/usr/local/sbin",
  "/opt/csw/bin","/opt/csw/sbin",
  "/usr/sfw/bin","/usr/sfw/sbin",
  "/usr/bin","/usr/sbin"
);
my @etcdirs=( 
  "/usr/local/etc", "/opt/csw/etc",
  "/usr/sfw/etc","/etc"
);
my %option=();
my $hostname;
my $hostip;
my $admingroup="wheel";
my $osname;
my %sdpamvals=( 
  "ENABLE_GROUP_SUPPORT" , "1",
  "INCL_EXCL_GROUPS"     , "1",
  "LIST_OF_GROUPS"       , "$admingroup"
);

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
  handle_output("Hostname is $hostname");
  handle_output("IP Address is $hostip");
  rsa_check();
  exit;
}

sub handle_output {
  my $output=$_[0];
  print "$output\n";
}

sub print_usage {
  print "\n";
  print "Usage: $script_name -$options\n";
  print "\n";
  print "-V: Print version information\n";
  print "-h: Print help\n";
  print "-c: Check what needs to be done to install RSA\n";
  print "\n";
  return;
}

sub get_host_info {
  $osname=`uname`;
  chomp($osname);
  $hostname=`hostname`;
  chomp($hostname);
  $hostip=`cat /etc/hosts |awk '{print \$1" "\$2}' |grep '$hostname\$' |awk '{print \$1}'`;
  chomp($hostip);
  return;
}

sub sudo_pam_check {
  my $sudobin=$_[0];
  my $sudopam=`strings $sudobin |grep pam`;
  if ($sudopam=~/with\-pam|libpam/) {
    handle_output("Sudo has PAM support");
  }
  else {
    handle_output("Warning: Sudo does not have PAM support");
  }
}

sub check_file_exists {
  my $filename=$_[0];
  if (! -f "$filename") {
    handle_output("Warning: File $filename does not exist");
    return("");
  }
  else {
    handle_output("File $filename exists");
    return($filename);
  }
}

sub check_dir_exists {
  my $dirname=$_[0];
  if (! -d "$dirname") {
    handle_output("Warning: Directory $dirname does not exist");
    return("");
  }
  else {
    handle_output("Directory $dirname exists");
    return($dirname);
  }
}

sub ace_status_check {
  my $acestatus="/opt/pam/bin/32bit/acestatus";
  my $acestatus=check_file_exists($acestatus);
  my @aceoutput;
  my $line;
  if (-f "$acestatus") {
    @aceoutput=`$acestatus 2>&1`;
    foreach $line (@aceoutput) {
      handle_output($line);
    }
  }
}

sub sd_pam_check {
  my $sdpam="/etc/sd_pam.conf";
  my @fileinfo;
  my $line;
  my $key;
  my $hash_param;
  my $hash_value;
  my $line_param;
  my $line_value;
  my %results;
  $sdpam=check_file_exists($sdpam);
  while (($hash_param,$hash_value)=each(%sdpamvals)) {
    $results{$hash_param}=0;
  }
  if (-f "$sdpam") {
    @fileinfo=`cat $sdpam`;
    foreach $line (@fileinfo) {
      chomp($line);
      while (($hash_param,$hash_value)=each(%sdpamvals)) {
        if ($line=~/^$hash_param/) {
          $results{$hash_param}=1;
          ($line_param,$line_value)=split("=",$line);
          if ($line_value!~/^$hash_value/) {
            handle_output("Parameter $hash_param correctly set to $hash_value");
          }
        }
      }
    }
    while (($hash_param,$hash_value)=each(%results)) {
      if ($hash_value == 0) {
        handle_output("File $sdpam does not contain $hash_value");
      }
    }
  }
}

sub check_file_perms {
  my $check_file=$_[0];
  my $check_user=$_[1];
  my $check_group=$_[2];
  my $check_perm=$_[3];
  my $file_mode;
  my $file_user;
  my $file_group;
  if ((-f "$check_file")||(-d "$check_file")) {
    $file_mode=(stat($check_file))[2];
    $file_mode=sprintf("%04o",$file_mode & 07777);
    $file_user=(stat($check_file))[4];
    $file_group=(stat($check_file))[5];
    $file_user=getpwuid($file_user);
    if ($file_mode != $check_perm) {
      handle_output("Warning: Permissions nf $check_file are not $check_perm");
    }
    else {
      handle_output("Permissions on $check_file are correctly set to $check_perm");
    }
    if ($file_user != $check_user) {
      handle_output("Warning: Ownership of $check_file is not $check_user");
    }
    else {
      handle_output("Ownership of $check_file is correctly set to $check_user");
    }
    if ($file_group != $check_group) {
      handle_output("Warning: Group ownership of $check_file is not $check_group");
    }
    else {
      handle_output("Group ownership of $check_file is correctly set to $check_group");
    }
  }
  return;
}

sub check_sdopts {
  my $acedir="/var/ace";
  my $sdopts="$acedir/sdopts.rec";
  my $fileinfo;
  check_file_perms($acedir,"root","root","640");
  if (-f "$sdopts") {
    $fileinfo=`cat $sdopts`;
    handle_output("File $sdopts contains:");
    handle_output($fileinfo);
    if ($fileinfo!~/$hostip/) {
      handle_output("File $sdopts contains incorrect IP");
    }
    else {
      handle_output("File $sdopts contains correct IP");
    }
  }
}

sub var_ace_check {
  my $acedir="/var/ace";
  my $sdconf="$acedir/sdconf.rec";
  my $sdopts="$acedir/sdopts.rec";
  check_file_perms($sdconf,"root","root","640");
  check_file_perms($sdopts,"root","root","640");
  $acedir=check_dir_exists($acedir);
  $sdconf=check_file_exists($sdconf);
  $sdopts=check_file_exists($sdopts);
  check_sdopts();
  return;
}

sub pam_sudo_check {
  my $pamfile;
  my $pamcheck;
  my @fileinfo;
  my $line;
  if ($osname=~/Linux/) {
    $pamfile="/etc/pam.d/sudo";
  }
  else {
    $pamfile="/etc/pam.conf";
  }
  if (-f "$pamfile") {
    $pamcheck=`cat $pamfile |grep securid |grep -v '^#'`;
    if ($pamcheck=~/securid/) {
      handle_output("RSA SecurID PAM Agent enabled");
      handle_output("File $pamfile contains:");
      handle_output($pamcheck);
    }
  }
  return;
}

sub opt_pam_check {
  my $pamdir="/opt/pam";
  $pamdir=check_dir_exists($pamdir);
  return;
}

sub sudo_group_check {
  my $sudoers=$_[0];
  my $groupcheck;
  if (-f "$sudoers") {
    $groupcheck=`cat $sudoers |grep '\%$admingroup' |grep -v '^#'`;
    if ($groupcheck!~/sysadmin/) {
      handle_output("File $sudoers does not contain a \%$admingroup entry");
      $groupcheck=`cat $sudoers |grep SYSADMIN |grep -v '^#'`;
      if ($groupcheck=~/SYSADMIN/) {
        handle_output("File $sudoers contains and old style SYSADMIN group which should be migrated to %sysadmin");
      }
    }
    else {
      handle_output("File $sudoers contains a \%$admingroup entry");
      handle_output($groupcheck);
    }
  }
  return;
}

sub etc_group_check {
  my $groupfile="/etc/group";
  my $groupcheck=`cat $groupfile |grep '^$admingroup'`;
  if ($groupcheck!~/$admingroup/) {
    handle_output("File $groupfile does not contain a $admingroup group entry");
  }
  else {
    $groupcheck=`cat $groupfile |grep '^$admingroup' |cut -f4 -d:`;
    if ($groupcheck!~/[A-z]/) {
      handle_output("File $groupfile has no members in $admingroup");
    }
    else {
      handle_output("File $groupfile contains a $admingroup group with members");
    }
  }
}

sub rsa_check {
  my $sudobin=get_sudobin();
  my $sudoers=get_sudoers();
  sudo_pam_check($sudobin);
  sudo_group_check($sudoers);
  etc_group_check();
  var_ace_check();
  opt_pam_check();
  pam_sudo_check();
  sd_pam_check();
  ace_status_check();
  return;
}

sub get_sudoers {
  my $etcdir;
  my $sudoetc;
  my @fileinfo;
  my $line;
  foreach $etcdir (@etcdirs) {
    $sudoetc="$etcdir/sudoers";
    if (-f "$sudoetc") {
      if ($option{'c'}) {
        handle_output("Sudoers file found at $sudoetc");
      }
      return($sudoetc);
    }
  }
}

sub get_sudobin {
  my $bindir;
  my $sudobin;
  my @fileinfo;
  foreach $bindir (@bindirs) {
    $sudobin="$bindir/sudo";
    if (-f "$sudobin") {
      if ($option{'c'}) {
        handle_output("Sudo found at $sudobin");
      }
      return($sudobin);
    }
  }
}