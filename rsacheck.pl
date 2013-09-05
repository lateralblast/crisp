#!/usr/bin/env perl

use strict;
use Getopt::Std;

# Name:         rsainstall.pl
# Version:      0.1.6
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
my $admin_group="wheel";
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
  handle_output("Hostname is $host_name");
  handle_output("IP Address is $host_ip");
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
  my $gz_file="$work_dir/$tar_file".".gz";
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
	$key_check=`gzcat $gz_file |tar -tf - |grep $check_file`;	
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
    if (-e "$gz_file") {
      system("cd $tmp_dir ; gzip -d $gz_file");
    }
    if ( -e "$tar_file") {
      system("cd $tmp_dir ; tar -xpf $tar_file");
			system("cd $ins_dir ; cat install_pam.sh |sed 's/^startup_screen\$/#&/g' > install_pam.sh.new");
			system("cd $ins_dir ; cat install_pam.sh.new > install_pam.sh");
    }
  }
  return;
}

sub uninstall_rsa {
  if (-e "$pam_dir") {
		system("$pam_dir/uninstall_pam.sh <<-UNINSTALL
			
			y
			y
			y
			UNINSTALL");
  }
}

sub install_rsa {
  if (-e "$ins_dir") {
    system("$ins_dir/install_pam.sh <<-INSTALL
				
			
			 
			INSTALL");
  }
}

sub sudo_pam_check {
  my $sudo_bin=$_[0];
  my $sudo_pam=`strings $sudo_bin |grep pam`;
  if ($sudo_pam=~/with\-pam|libpam/) {
    handle_output("Sudo has PAM support");
  }
  else {
    handle_output("Warning: Sudo does not have PAM support");
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
    handle_output("Warning: File $file_name does not exist");
    return("");
  }
  else {
    handle_output("File $file_name exists");
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
    handle_output("Warning: Directory $dir_name does not exist");
    return("");
  }
  else {
    handle_output("Directory $dir_name exists");
    return($dir_name);
  }
}

sub ace_status_check {
  my $ace_status="$pam_dir/bin/32bit/acestatus";
  my $ace_status=check_file_exists($ace_status);
  my @ace_output;
  my $line;
  if (-f "$ace_status") {
    @ace_output=`$ace_status 2>&1`;
    foreach $line (@ace_output) {
      handle_output($line);
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
            handle_output("Parameter $hash_param correctly set to $hash_value");
          }
          else {
            $change=1;
            if ($option{'f'}) {
              if (!-e "$sd_pam_file.prersa") {
                system("cp $sd_pam_file $sd_pam_file.prersa");
              }
              $line=~s/$line_value/$hash_value/;
              @file_info[$counter]="$line\n";
            }
          }
        }
      }
    }
    if (!$option{'f'}) {
      while (($hash_param,$hash_value)=each(%results)) {
        if ($hash_value == 0) {
          handle_output("File $sd_pam_file does not contain $hash_value");
        }
      }
    }
    else {
      if ($change eq 1) {
        open (OUTPUT,">",$sd_pam_file);
        foreach $line (@file_info) {
          print OUTPUT $line;
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
      handle_output("Warning: Permissions nf $check_file are not $check_perm");
      if ($option{'f'}) {
        handle_output("Fixing");
        system("chmod $check_perm $check_file");
      }
    }
    else {
      handle_output("Permissions on $check_file are correctly set to $check_perm");
    }
    if ($file_user != $check_user) {
      handle_output("Warning: Ownership of $check_file is not $check_user");
      if ($option{'f'}) {
        handle_output("Fixing");
        system("chown $check_user $check_file");
      }
    }
    else {
      handle_output("Ownership of $check_file is correctly set to $check_user");
    }
    if ($file_group != $check_group) {
      handle_output("Warning: Group ownership of $check_file is not $check_group");
      if ($option{'f'}) {
        handle_output("Fixing");
        system("chgrp $check_group $check_file");
      }
    }
    else {
      handle_output("Group ownership of $check_file is correctly set to $check_group");
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
    handle_output("File $sdopts_file contains:");
    handle_output($file_info);
    if ($file_info!~/$host_ip/) {
      handle_output("File $sdopts_file contains incorrect IP");
      handle_output("Entry should be: $sdopts_line\n");
      if ($option{'f'}) {
        handle_output("Fixing $sdopts_file");
        open(OUTPUT,">",$sdopts_file);
        print OUTPUT "$sdopts_line\n";
        close(OUTPUT)
      }
    }
    else {
      handle_output("File $sdopts_file contains correct IP");
    }
  }
}

sub var_ace_check {
	my $tmp_file="/tmp/sdopts.rec";
  $ace_dir=check_dir_exists($ace_dir);
	if ($option{'f'}) {
		if (!-e "$sdconf_file") {
			system("cp $tmp_file $sdconf_file");
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
  my $pam_check;
  my @file_info;
  my $line;
  if ($os_name=~/Linux/) {
    $pam_file="/etc/pam.d/sudo";
  }
  else {
    $pam_file="/etc/pam.conf";
  }
  if (-f "$pam_file") {
    $pam_check=`cat $pam_file |grep securid |grep -v '^#'`;
    if ($pam_check=~/securid/) {
      handle_output("RSA SecurID PAM Agent enabled");
      handle_output("File $pam_file contains:");
      handle_output($pam_check);
    }
    else {
      handle_output("File $pam_file does not contain securid");
      if ($option{'f'}) {
        handle_output("Fixing $pam_file");
        system("cp $pam_file $pam_file.prersa");
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
      handle_output("File $sudoers does not contain a \%$admin_group entry");
      $group_check=`cat $sudoers |grep $uc_admin_group |grep -v '^#'`;
      if ($group_check=~/$uc_admin_group/) {
        handle_output("File $sudoers contains and old style $uc_admin_group group which should be migrated to \%$admin_group");
      }
    }
    else {
      handle_output("File $sudoers contains a \%$admin_group entry");
      handle_output($group_check);
    }
  }
  return;
}

sub etc_group_check {
  my $groupfile="/etc/group";
  my $group_check=`cat $groupfile |grep '^$admin_group'`;
  if ($group_check!~/$admin_group/) {
    handle_output("File $groupfile does not contain a $admin_group group entry");
  }
  else {
    $group_check=`cat $groupfile |grep '^$admin_group' |cut -f4 -d:`;
    if ($group_check!~/[A-z]/) {
      handle_output("File $groupfile has no members in $admin_group");
    }
    else {
      handle_output("File $groupfile contains a $admin_group group with members");
    }
  }
}

sub rsa_check {
  my $sudo_bin=get_sudo_bin();
  my $sudoers=get_sudoers();
  sudo_pam_check($sudo_bin);
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
  my $etc_dir;
  my $sudoetc;
  my @file_info;
  my $line;
  foreach $etc_dir (@etc_dirs) {
    $sudoetc="$etc_dir/sudoers";
    if (-f "$sudoetc") {
      if ($option{'c'}) {
        handle_output("Sudoers file found at $sudoetc");
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
        handle_output("Sudo found at $sudo_bin");
      }
      return($sudo_bin);
    }
  }
}
__DATA__
