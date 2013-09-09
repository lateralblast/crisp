#!/usr/bin/env perl

use strict;
use Getopt::Std;

# Name:         rsainstall.pl
# Version:      0.1.8
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
#               0.0.9 Mon 26 Aug 2013 08:33:46 EST
#               Fixed permissions check to include directories
#               0.1.0 Wed  4 Sep 2013 11:30:31 EST
#               Added initial install code
#               0.1.1 Wed  4 Sep 2013 11:53:30 EST
#               Added code to create installer script
#               0.1.2 Wed  4 Sep 2013 12:26:48 EST
#               Added code to fix things
#               0.1.3 Wed  4 Sep 2013 14:06:53 EST
#               Added code to update pam.conf and sd_pam.conf
#               0.1.4 Thu  5 Sep 2013 06:32:25 EST
#               Added code to create installer with packed tar file
#               0.1.5 Fri  6 Sep 2013 08:34:16 EST
#               Improved install script creation
#               0.1.6 Fri  6 Sep 2013 09:37:21 EST
#               Fixed etc directory for CSWsudo package 
#               0.1.7 Fri  6 Sep 2013 16:53:29 EST
#               Improved installation and uninstallation
#               0.1.8 Mon  9 Sep 2013 08:57:40 EST
#               Improved user feedback messages

my $script_name=$0;
my $work_dir=".";
my $install_script="rsainstall.pl";
my $script_version=`cat $script_name | grep '^# Version' |awk '{print \$3}'`; 
my $options="IVcfhiu";
my @bin_dirs=( 
  "/usr/local/bin","/usr/local/sbin",
  "/opt/csw/bin","/opt/csw/sbin",
  "/usr/sfw/bin","/usr/sfw/sbin",
  "/usr/bin","/usr/sbin"
);
my @etc_dirs=( 
  "/usr/local/etc", "/etc/opt/csw",
  "/usr/sfw/etc","/etc"
);
my %option=();
my $host_name;
my $host_ip;
my $admin_group="sysadmin";
my $uc_admin_group=uc($admin_group);
my $os_name;
my %sd_pam_vals=( 
  "ENABLE_GROUP_SUPPORT" , "1",
  "INCL_EXCL_GROUPS"     , "1",
  "LIST_OF_GROUPS"       , "$admin_group"
);
my $rsa_version="7.1.0.149.01_14_13_00_07_15";
my $tmp_dir="/tmp";
my $pam_dir="/opt/pam";
my $ace_dir="/var/ace";
my $sdopts_file="$ace_dir/sdopts.rec";
my $sdconf_file="$ace_dir/sdconf.rec";
my $pam_name="PAM-Agent_v".$rsa_version;
my $ins_dir="$tmp_dir/$pam_name";

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

if ($option{'i'}) {
  $option{'f'}=1;
  get_host_info();  
  extract_file();
  install_rsa();
  rsa_check();
  exit;
}

if ($option{'u'}) {
  uninstall_rsa();
  exit;
}

if ($option{'I'}) {
  create_install_script();
  exit;
}

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

sub get_host_info {
  $os_name=`uname`;
  chomp($os_name);
  $host_name=`hostname`;
  chomp($host_name);
  $host_ip=`cat /etc/hosts |awk '{print \$1" "\$2}' |grep '$host_name'`;
  if ($host_ip=~/\./) {
    $host_ip=`cat /etc/hosts |awk '{print \$1" "\$3}' |grep '$host_name'`;
  }
  ($host_ip,$host_name)=split(/\s+/,$host_ip);
  chomp($host_ip);
  return;
}

sub create_install_script {
  my $tar_file="$work_dir/$pam_name".".tar";
  my $gz_file="$tar_file".".gz";
  my $key_check;
  my $check_file="sdconf.rec";
  if (!-e "$gz_file") {
    if ( -e "$tar_file") {
      system("gzip $tar_file");
    }
    else {
      print "Copy $tar_file (or gzipped version) into current directory and re-run script\n";
      exit;
    }
  }
  if ($script_name=~/$install_script/) {
    print "You should be running the original script not the packed script!\n";
    exit;
  }
  $key_check=`gzip -dc $gz_file |tar -tf - |grep $check_file`;  
  if ($key_check!~/$check_file/) {
    if (! -e "$check_file") {
      print "Copy $check_file into current directory and re-run script\n";
      exit;
    }
    print "File $check_file not in archive\n";
    print "Adding $check_file to archive\n";
    system("gzip -d $gz_file");
    system("tar -rf $tar_file $check_file");
    system("gzip $tar_file");
  }
  system("cp $script_name $work_dir/$install_script");
  system("cat $gz_file >> $work_dir/$install_script");
  return;
}

sub extract_file {
  my $tar_file="$tmp_dir/$pam_name".".tar";
  my $gz_file="$tar_file".".gz";
  if (! -e "$ins_dir") {
    if (! -e "$gz_file") {
      open(OUTFILE,">","$gz_file");
      while (<DATA>) {
        print OUTFILE $_;
      }
    }
    if (! -e "$tar_file") {
      if (-e "$gz_file") {
        system("cd $tmp_dir ; gzip -d $gz_file");
      }
    }
    if ( -e "$tar_file") {
      system("cd $tmp_dir ; tar -xpf $tar_file");
      system("cd $ins_dir ; cat install_pam.sh |sed 's/^startup_screen\$/#&/g' > install_pam.sh.new");
      system("cd $ins_dir ; cat install_pam.sh.new > install_pam.sh");
    }
  }
  if (-e "$ins_dir") {
    var_ace_check();
  }
  else {
    print "Directory $ins_dir does not exist\n";
  }
  return;
}

sub uninstall_rsa {
  my $sudoers=get_sudoers();
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

sub install_rsa {
  if (-e "$ins_dir") {
    system("$ins_dir/install_pam.sh <<-INSTALL
        
      
       
      INSTALL");
  }
  install_clean_up();
}

sub sudo_pam_check {
  my $sudo_bin=$_[0];
  my $sudo_pam=`strings $sudo_bin |grep pam`;
  if ($sudo_pam=~/with\-pam|libpam/) {
    print "Sudo has PAM support\n";
  }
  else {
    print "Warning: Sudo does not have PAM support\n";
  }
}

sub check_file_exists {
  my $file_name=$_[0];
  if ($option{'f'}) {
    if (! -f "$file_name") {
      system("tocuh $file_name");
    }
  }
  if (! -f "$file_name") {
    print "Warning: File $file_name does not exist\n";
    return("");
  }
  else {
    print "File $file_name exists\n";
    return($file_name);
  }
}

sub check_dir_exists {
  my $dir_name=$_[0];
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

sub ace_status_check {
  my $ace_status="$pam_dir/bin/64bit/acestatus";
  my $ace_status=check_file_exists($ace_status);
  my @ace_output;
  my $line;
  if (! -e "$ace_status") {
    $ace_status=~s/64/32/g;
    $ace_status=check_file_exists($ace_status);
  }
  if (-f "$ace_status") {
    @ace_output=`$ace_status 2>&1`;
    foreach $line (@ace_output) {
      chomp($line);
      print "$line\n";
    }
  }
}

sub sd_pam_check {
  my $sd_pam_file="/etc/sd_pam.conf";
  my @file_info;
  my $line;
  my $key;
  my $hash_param;
  my $hash_value;
  my $line_param;
  my $line_value;
  my %results;
  my $counter;
  my $change=0;
  $sd_pam_file=check_file_exists($sd_pam_file);
  while (($hash_param,$hash_value)=each(%sd_pam_vals)) {
    $results{$hash_param}=0;
  }
  if (-f "$sd_pam_file") {
    @file_info=`cat $sd_pam_file`;
    for ($counter=0; $counter<@file_info; $counter++) {
      $line=@file_info[$counter];
      chomp($line);
      while (($hash_param,$hash_value)=each(%sd_pam_vals)) {
        if ($line=~/^$hash_param/) {
          $results{$hash_param}=1;
          ($line_param,$line_value)=split("=",$line);
          if ($line_value!~/^$hash_value/) {
            print "Parameter $hash_param correctly set to $hash_value\n";
          }
          else {
            $change=1;
            if ($option{'f'}) {
              if (!-e "$sd_pam_file.prersa") {
                system("cp $sd_pam_file $sd_pam_file.prersa");
              }
              $line=~s/$line_value/$hash_value/;
              @file_info[$counter]=$line;
            }
          }
        }
      }
    }
    if (!$option{'f'}) {
      while (($hash_param,$hash_value)=each(%results)) {
        if ($hash_value == 0) {
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

sub check_sdopts {
  my $file_info;
  my $sdopts_line="CLIENT_IP=$host_ip";
  if ($option{'f'}) {
    if (! -f "$sdopts_file") {
      system("touch $sdopts_file");
    }
  }
  check_file_perms($ace_dir,"root","root","750");
  if (-f "$sdopts_file") {
    $file_info=`cat $sdopts_file |head -1`;
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
}

sub var_ace_check {
  my $tmp_file="/tmp/sdconf.rec";
  $ace_dir=check_dir_exists($ace_dir);
  if ($option{'f'}) {
    if (!-e "$sdconf_file") {
      system("cp $tmp_file $sdconf_file");
      system("rm $tmp_file");
    }
  }
  $sdconf_file=check_file_exists($sdconf_file);
  $sdopts_file=check_file_exists($sdopts_file);
  check_file_perms($sdconf_file,"root","root","640");
  check_file_perms($sdopts_file,"root","root","640");
  check_sdopts();
  return;
}

sub pam_sudo_check {
  my $pam_file;
  my $tmp_file="/tmp/pam.sudo";
  my $pam_check;
  my @file_info;
  my $line;
  if ($os_name=~/Linux/) {
    $pam_file="/etc/pam.d/sudo";
  }
  else {
    $pam_file="/etc/pam.conf";
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
    if (-f "$pam_file") {
      $pam_check=`cat $pam_file |grep securid |grep -v '^#'`;
      if ($pam_check=~/securid/) {
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
          if ($os_name=~/Linux/) {
            system("cat $pam_file |sed 's/^auth/#\&/' > $tmp_file");
            system("cat $tmp_file > $pam_file");
            system("tm $tmp_file");
          }
          open(OUTPUT,">>",$pam_file);
          if ($os_name=~/Linux/) {
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

sub opt_pam_check {
  $pam_dir=check_dir_exists($pam_dir);
  return;
}

sub sudo_group_check {
  my $sudoers=$_[0];
  my $group_check;
  if (-f "$sudoers") {
    $group_check=`cat $sudoers |grep '\%$admin_group' |grep -v '^#'`;
    if ($group_check!~/$admin_group/) {
      print "File $sudoers does not contain a \%$admin_group entry\n";
      $group_check=`cat $sudoers |grep $uc_admin_group |grep -v '^#'`;
      if ($group_check=~/$uc_admin_group/) {
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

sub sudo_passwd_check {
  my $sudoers=$_[0];
  my $sudotmp="/tmp/sudoers";
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
      $passwd_check=`cat $sudoers |grep '\%$admin_group' |grep 'NOPASSWD' |grep -v '^#'`;
      if ($passwd_check=~/NOPASSWD/) {
        print "File $sudoers contains a NOPASSWD entry\n";
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

sub etc_group_check {
  my $sudoers;
  my $groupfile="/etc/group";
  my $group_check=`cat $groupfile |grep '^$admin_group'`;
  if ($group_check!~/$admin_group/) {
    print "File $groupfile does not contain a $admin_group group entry\n";
  }
  else {
    $group_check=`cat $groupfile |grep '^$admin_group' |cut -f4 -d:`;
    if ($group_check!~/[A-z]/) {
      print "File $groupfile has no members in $admin_group\n";
    }
    else {
      print "File $groupfile contains a $admin_group group with members\n";
      if ($option{'f'}) {
        $sudoers=get_sudoers();
        sudo_passwd_check($sudoers);
      }
    }
  }
}

sub rsa_check {
  my $sudo_bin=get_sudo_bin();
  my $sudoers=get_sudoers();
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

sub get_sudoers {
  my $etc_dir;
  my $sudoetc;
  my @file_info;
  my $line;
  foreach $etc_dir (@etc_dirs) {
    $sudoetc="$etc_dir/sudoers";
    if (-f "$sudoetc") {
      if ($option{'c'}) {
        print "Sudoers file found at $sudoetc\n";
      }
      return($sudoetc);
    }
  }
}

sub get_sudo_bin {
  my $bin_dir;
  my $sudo_bin;
  my @file_info;
  foreach $bin_dir (@bin_dirs) {
    $sudo_bin="$bin_dir/sudo";
    if (-f "$sudo_bin") {
      if ($option{'c'}) {
        print "Sudo found at $sudo_bin\n";
      }
      return($sudo_bin);
    }
  }
}

sub install_clean_up {
  system("rm -rf /tmp/PAM*");
}

__DATA__
