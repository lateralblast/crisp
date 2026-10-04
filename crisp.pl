#!/usr/bin/env perl

# Name:         crisp.pl
# Version:      0.5.0
# Release:      1
# License:      CC BY-NC-SA 4.0 (Creative Commons Attribution-NonCommercial-ShareAlike)
#               https://creativecommons.org/licenses/by-nc-sa/4.0/legalcode
# Group:        System
# Source:       N/A
# URL:          N/A
# Distribution: Solaris / Linux
# Vendor:       Lateral Blast
# Packager:     Richard Spindler <richard@lateralblast.com.au>
# Description:  Script to check RSA SecurID PAM Agent is installed correctly

use strict;
use warnings;
use Cwd qw(getcwd);
use File::Basename;
use File::Copy;
use File::Path qw(make_path remove_tree);
use Getopt::Std;
use POSIX qw(uname);
use Sys::Hostname;

my $script_name    = $0;
my $work_dir       = ".";
my $start_script   = basename($script_name);
my $install_script = "rsainstall.pl";
my $script_version = get_script_version();
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
my $host_name      = "";
my $host_ip        = "";
my $admin_group    = "sysadmin";
my $uc_admin_group = uc($admin_group);
my $os_name        = "";
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

main();

# Main routine
# Parse the options and run the requested mode

sub main {
  if (!@ARGV || !getopts($options,\%option)) {
    print_usage();
    exit(1);
  }
  # If given -h print usage
  if ($option{'h'}) {
    print_usage();
    exit(0);
  }
  # Print script version
  if ($option{'V'}) {
    print_version();
    exit(0);
  }
  # Run check
  if ($option{'c'}) {
    get_host_info();
    print "Hostname is $host_name\n";
    print "IP Address is $host_ip\n";
    rsa_check();
    exit(0);
  }
  # If running in install mode, set the fix flag to 1
  if ($option{'i'}) {
    $option{'f'} = 1;
    get_host_info();
    extract_file();
    install_rsa();
    rsa_check();
    exit(0);
  }
  # If given -u uninstall
  if ($option{'u'}) {
    get_os_name();
    uninstall_rsa();
    exit(0);
  }
  # If given -I create installer script
  if ($option{'I'}) {
    create_install_script();
    exit(0);
  }
  return;
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

# Subroutine to print script version

sub print_version {
  print "$script_version\n";
  return;
}

# Subroutine to get the script version from the header of the script
# Only the start of the script is read as the packed script has binary data at the end

sub get_script_version {
  my $fh;
  my $line;
  my $version = "unknown";
  if (open($fh,"<",$0)) {
    while ($line = <$fh>) {
      if ($line =~ /^# Version:\s+(\S+)/) {
        $version = $1;
        last;
      }
    }
    close($fh);
  }
  return($version);
}

# Subroutine to quote a string for use in a shell command

sub shell_quote {
  my $string = $_[0];
  $string =~ s/'/'\\''/g;
  return("'$string'");
}

# Subroutine to run a command without a shell

sub run_cmd {
  my @command = @_;
  if (system(@command) != 0) {
    warn "Warning: Command failed: @command\n";
    return(0);
  }
  return(1);
}

# Subroutine to run a command in a directory

sub run_in_dir {
  my ($dir_name,@command) = @_;
  my $cwd = getcwd();
  my $status;
  if (!chdir($dir_name)) {
    warn "Warning: Cannot change to $dir_name: $!\n";
    return(0);
  }
  $status = run_cmd(@command);
  chdir($cwd);
  return($status);
}

# Subroutine to run a command and feed it answers on standard input

sub run_with_input {
  my ($input,@command) = @_;
  my $fh;
  if (!open($fh,"|-",@command)) {
    warn "Warning: Cannot run @command: $!\n";
    return(0);
  }
  print $fh $input;
  close($fh);
  return(1);
}

# Subroutine to read a text file into a list of lines

sub read_file {
  my $file_name = $_[0];
  my $fh;
  my @lines;
  if (!open($fh,"<",$file_name)) {
    warn "Warning: Cannot read $file_name: $!\n";
    return();
  }
  @lines = <$fh>;
  close($fh);
  return(@lines);
}

# Subroutine to write (">") or append (">>") lines to a text file

sub write_file {
  my ($file_name,$mode,@lines) = @_;
  my $fh;
  if (!open($fh,$mode,$file_name)) {
    warn "Warning: Cannot write $file_name: $!\n";
    return(0);
  }
  print $fh @lines;
  close($fh);
  return(1);
}

# Subroutine to get the OS name

sub get_os_name {
  $os_name = (uname())[0];
  return;
}

# Subroutine to get host information

sub get_host_info {
  my @fields;
  my $line;
  my $host_addr;
  get_os_name();
  $host_name = hostname();
  $host_name =~ s/\..*$//;
  $host_ip   = "";
  foreach $line (read_file("/etc/hosts")) {
    next if ($line =~ /localhost|^\s*#/);
    @fields    = split(' ',$line);
    $host_addr = shift(@fields);
    if (defined($host_addr) && grep(/^\Q$host_name\E(\.|$)/,@fields)) {
      $host_ip = $host_addr;
      last;
    }
  }
  if ($host_ip !~ /\./) {
    print "Warning: Could not find an IP address for $host_name in /etc/hosts\n";
  }
  return;
}

# Subroutine to create installer script
# This creates a copy of the script and embeds the tar.gz to the end of it

sub create_install_script {
  my $tar_file   = "$work_dir/$pam_name".".tar";
  my $gz_file    = "$tar_file".".gz";
  my $dest_file  = "$work_dir/$install_script";
  my $check_file = "sdconf.rec";
  my $key_check;
  my $in_fh;
  my $out_fh;
  my @lines;
  # Check the the PAM Agent .tar.gz file exists
  # If the gz file doesn't exist but the tar does, gzip the tar
  if (!-e $gz_file) {
    if (-e $tar_file) {
      run_cmd("gzip",$tar_file);
    }
    else {
      print "Copy $tar_file (or gzipped version) into current directory and re-run script\n";
      exit(1);
    }
  }
  # Check that we are not running the created script
  if ($start_script eq $install_script) {
    print "You should be running the original script not the packed script!\n";
    exit(1);
  }
  # Check whether the server config file (sdconf.rec) is in the .tar.gz
  # This file is required for the install
  $key_check = `gzip -dc @{[shell_quote($gz_file)]} | tar -tf -`;
  if ($key_check !~ /\Q$check_file\E/) {
    if (!-e $check_file) {
      print "Copy $check_file into current directory and re-run script\n";
      exit(1);
    }
    # If the file is not in the archive, then add it from the current directory
    print "File $check_file not in archive\n";
    print "Adding $check_file to archive\n";
    run_cmd("gzip","-d",$gz_file);
    run_cmd("tar","-rf",$tar_file,$check_file);
    run_cmd("gzip",$tar_file);
  }
  # Copy the script and embed the .tar.gz at the end
  @lines = read_file($script_name);
  foreach my $line (@lines) {
    $line =~ s/# Name:         \Q$start_script\E/# Name:         $install_script/g;
  }
  write_file($dest_file,">",@lines) or exit(1);
  if (!open($in_fh,"<",$gz_file)) {
    warn "Warning: Cannot read $gz_file: $!\n";
    exit(1);
  }
  if (!open($out_fh,">>",$dest_file)) {
    warn "Warning: Cannot write $dest_file: $!\n";
    exit(1);
  }
  binmode($in_fh);
  binmode($out_fh);
  {
    local $/;
    print {$out_fh} <$in_fh>;
  }
  close($in_fh);
  close($out_fh);
  chmod(0755,$dest_file);
  return;
}

# Subroutine to extract the .tar.gz from the install script

sub extract_file {
  my $tar_file = "$tmp_dir/$pam_name".".tar";
  my $gz_file  = "$tar_file".".gz";
  my $out_fh;
  my @lines;
  # Check to see it hasn't already been extracted
  # Useful for testing purposes to not have to extract every time
  # In this case disable the clean up subroutine
  if (!-e $ins_dir) {
    # Extract the .tar.gz from the script
    if (!-e $gz_file) {
      if (!open($out_fh,">",$gz_file)) {
        warn "Warning: Cannot write $gz_file: $!\n";
        exit(1);
      }
      binmode($out_fh);
      binmode(DATA);
      {
        local $/;
        print {$out_fh} <DATA>;
      }
      close($out_fh);
    }
    # Extract the .tar for the .tar.gz
    if (!-e $tar_file) {
      if (-e $gz_file) {
        run_cmd("gzip","-d",$gz_file);
      }
    }
    # Untar the tar file and fix the installer script to ignore the license message
    if (-e $tar_file) {
      run_in_dir($tmp_dir,"tar","-xpf",$tar_file);
      if (-e "$ins_dir/install_pam.sh") {
        @lines = read_file("$ins_dir/install_pam.sh");
        foreach my $line (@lines) {
          $line =~ s/^startup_screen$/#startup_screen/;
        }
        write_file("$ins_dir/install_pam.sh",">",@lines);
      }
    }
  }
  # Check /var/ace
  if (-e $ins_dir) {
    var_ace_check();
  }
  else {
    print "Directory $ins_dir does not exist\n";
  }
  return;
}

# Subroutine to run the uninstall script
# Pipes in the answers to the questions

sub uninstall_rsa {
  my $sudoers = get_sudoers();
  if (-e $pam_dir) {
    run_with_input("\ny\ny\ny\n","$pam_dir/uninstall_pam.sh");
  }
  sudo_passwd_check($sudoers);
  pam_sudo_check();
  return;
}

# Subroutine to run the install script
# Pipes in the answers to the questions

sub install_rsa {
  if (-e $ins_dir) {
    run_with_input("\n\n\n","$ins_dir/install_pam.sh");
  }
  install_clean_up();
  return;
}

# Subroutine to check that sudo is compiled with PAM support

sub sudo_pam_check {
  my $sudo_bin = $_[0];
  my $fh;
  my $sudo_pam = "";
  if ($sudo_bin eq "") {
    print "Warning: Sudo not found\n";
    return;
  }
  if (open($fh,"<",$sudo_bin)) {
    binmode($fh);
    local $/;
    $sudo_pam = <$fh>;
    close($fh);
  }
  else {
    warn "Warning: Cannot read $sudo_bin: $!\n";
  }
  if ($sudo_pam =~ /with\-pam|libpam/) {
    print "Sudo has PAM support\n";
  }
  else {
    print "Warning: Sudo does not have PAM support\n";
  }
  return;
}

# Subroutine to check a file exists

sub check_file_exists {
  my $file_name = $_[0];
  if ($option{'f'}) {
    if (!-e $file_name) {
      write_file($file_name,">>","");
    }
  }
  if (!-e $file_name) {
    print "Warning: File $file_name does not exist\n";
    return("");
  }
  print "File $file_name exists\n";
  return($file_name);
}

# Subroutine to check a directory exists

sub check_dir_exists {
  my $dir_name = $_[0];
  if ($option{'f'}) {
    if (!-d $dir_name) {
      eval { make_path($dir_name) };
    }
  }
  if (!-d $dir_name) {
    print "Warning: Directory $dir_name does not exist\n";
    return("");
  }
  print "Directory $dir_name exists\n";
  return($dir_name);
}

# Subroutine to run acestatus

sub ace_status_check {
  my $ace_path   = "$pam_dir/bin/64bit/acestatus";
  my $ace_status = check_file_exists($ace_path);
  my @ace_output;
  my $line;
  if (!-e $ace_status) {
    $ace_path   =~ s/64/32/g;
    $ace_status = check_file_exists($ace_path);
  }
  if (-e $ace_status) {
    @ace_output = `@{[shell_quote($ace_status)]} 2>&1`;
    foreach $line (@ace_output) {
      chomp($line);
      print "$line\n";
    }
  }
  return;
}

# Subroutine to check entries in /etc/sd_pam.conf

sub sd_pam_check {
  my $sd_pam_file = "/etc/sd_pam.conf";
  my @file_info;
  my $line;
  my $hash_param;
  my $line_value;
  my %results;
  my $counter;
  my $change = 0;
  $sd_pam_file = check_file_exists($sd_pam_file);
  foreach $hash_param (keys(%sd_pam_vals)) {
    $results{$hash_param} = 0;
  }
  if (-e $sd_pam_file) {
    @file_info = read_file($sd_pam_file);
    chomp(@file_info);
    for ($counter = 0; $counter < @file_info; $counter++) {
      $line = $file_info[$counter];
      foreach $hash_param (keys(%sd_pam_vals)) {
        if ($line =~ /^$hash_param/) {
          $results{$hash_param} = 1;
          (undef,$line_value) = split(" = ",$line);
          if (defined($line_value) && $line_value =~ /^\Q$sd_pam_vals{$hash_param}\E/) {
            print "Parameter $hash_param correctly set to $sd_pam_vals{$hash_param}\n";
          }
          else {
            print "Warning: Parameter $hash_param is not set to $sd_pam_vals{$hash_param}\n";
            $change = 1;
            if ($option{'f'}) {
              if (!-e "$sd_pam_file.prersa") {
                copy($sd_pam_file,"$sd_pam_file.prersa");
              }
              $file_info[$counter] = "$hash_param = $sd_pam_vals{$hash_param}";
            }
          }
        }
      }
    }
    if (!$option{'f'}) {
      foreach $hash_param (keys(%results)) {
        if ($results{$hash_param} == 0) {
          print "File $sd_pam_file does not contain $hash_param\n";
        }
      }
    }
    elsif ($change) {
      write_file($sd_pam_file,">",map { "$_\n" } @file_info);
    }
  }
  return;
}

# Subroutine to convert a uid or gid to a name
# Returns the id if there is no name

sub get_name {
  my $id   = $_[0];
  my $user = $_[1];
  my $name = $user ? getpwuid($id) : getgrgid($id);
  return(defined($name) ? $name : $id);
}

# Subroutine to check file permissions

sub check_file_perms {
  my ($check_file,$check_user,$check_group,$check_perm) = @_;
  my @file_stat;
  my $file_mode;
  my $file_user;
  my $file_group;
  my $uid;
  my $gid;
  if (-e $check_file) {
    @file_stat  = stat($check_file);
    $file_mode  = sprintf("%04o",$file_stat[2] & 07777);
    $file_user  = get_name($file_stat[4],1);
    $file_group = get_name($file_stat[5],0);
    if (oct($file_mode) != oct($check_perm)) {
      print "Warning: Permissions on $check_file are not $check_perm\n";
      if ($option{'f'}) {
        print "Fixing permissions on $check_file\n";
        chmod(oct($check_perm),$check_file);
      }
    }
    else {
      print "Permissions on $check_file are correctly set to $check_perm\n";
    }
    if ($file_user ne $check_user) {
      print "Warning: Ownership of $check_file is not $check_user\n";
      if ($option{'f'}) {
        print "Fixing ownership of $check_file\n";
        $uid = getpwnam($check_user);
        if (defined($uid)) {
          chown($uid,-1,$check_file);
        }
      }
    }
    else {
      print "Ownership of $check_file is correctly set to $check_user\n";
    }
    if ($file_group ne $check_group) {
      print "Warning: Group ownership of $check_file is not $check_group\n";
      if ($option{'f'}) {
        print "Fixing group ownership of $check_file\n";
        $gid = getgrnam($check_group);
        if (defined($gid)) {
          chown(-1,$gid,$check_file);
        }
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
  my @file_info;
  my $first_line;
  my $sdopts_line = "CLIENT_IP = $host_ip";
  if ($host_ip !~ /\./) {
    print "Warning: No IP address found, not checking $sdopts_file\n";
    return;
  }
  if ($option{'f'}) {
    if (!-e $sdopts_file) {
      write_file($sdopts_file,">>","");
    }
  }
  check_file_perms($ace_dir,"root","root","750");
  if (-e $sdopts_file) {
    @file_info  = read_file($sdopts_file);
    $first_line = defined($file_info[0]) ? $file_info[0] : "";
    chomp($first_line);
    print "File $sdopts_file contains:\n";
    print "$first_line\n";
    if ($first_line !~ /\Q$host_ip\E/) {
      print "File $sdopts_file contains incorrect IP\n";
      print "Entry should be: $sdopts_line\n";
      if ($option{'f'}) {
        print "Fixing $sdopts_file\n";
        write_file($sdopts_file,">","$sdopts_line\n");
      }
    }
    else {
      print "File $sdopts_file contains correct IP\n";
    }
  }
  elsif ($option{'f'}) {
    print "Fixing $sdopts_file\n";
    write_file($sdopts_file,">","$sdopts_line\n");
  }
  return;
}

# Subroutine to check that /var/ace exists
# and the correct files and permissions are in place

sub var_ace_check {
  my $tmp_file = "$tmp_dir/sdconf.rec";
  $ace_dir = check_dir_exists($ace_dir);
  # If running installer copy the sdconf.rec file into place
  if ($option{'f'}) {
    if (!-e $sdconf_file && -e $tmp_file) {
      copy($tmp_file,$sdconf_file);
      unlink($tmp_file);
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
  my @file_info;
  my @pam_check;
  if ($os_name =~ /Linux/) {
    $pam_file = "/etc/pam.d/sudo";
  }
  else {
    $pam_file = "/etc/pam.conf";
  }
  if ($option{'u'}) {
    if (-e "$pam_file.prersa") {
      print "Restoring $pam_file\n";
      copy("$pam_file.prersa",$pam_file);
      unlink("$pam_file.prersa");
    }
  }
  elsif (-e $pam_file) {
    @file_info = read_file($pam_file);
    @pam_check = grep { /securid/ && !/^#/ } @file_info;
    if (@pam_check) {
      print "RSA SecurID PAM Agent enabled\n";
      print "File $pam_file contains:\n";
      print join("",@pam_check),"\n";
    }
    else {
      print "File $pam_file does not contain securid\n";
      if ($option{'f'}) {
        print "Fixing $pam_file\n";
        copy($pam_file,"$pam_file.prersa");
        if ($os_name =~ /Linux/) {
          foreach my $line (@file_info) {
            $line =~ s/^auth/#auth/;
          }
          write_file($pam_file,">",@file_info);
          write_file($pam_file,">>","auth\trequired\tpam_securid.so reserve\n");
        }
        else {
          write_file($pam_file,">>","sudo\tauth\trequired\tpam_securid.so reserve\n");
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
  my @sudoers_info;
  my @group_check;
  if (-e $sudoers) {
    @sudoers_info = read_file($sudoers);
    @group_check  = grep { /\%\Q$admin_group\E/ && !/^#/ } @sudoers_info;
    if (!@group_check) {
      print "File $sudoers does not contain a \%$admin_group entry\n";
      @group_check = grep { /\Q$uc_admin_group\E/ && !/^#/ } @sudoers_info;
      if (@group_check) {
        print "File $sudoers contains an old style $uc_admin_group group which should be migrated to \%$admin_group\n";
      }
    }
    else {
      print "File $sudoers contains a \%$admin_group entry\n";
      print join("",@group_check),"\n";
    }
  }
  return;
}

# Subroutine to check that sudoers file requires a password
# to escalate privileges (ie no NOPASSWD entry)

sub sudo_passwd_check {
  my $sudoers = $_[0];
  my @sudoers_info;
  my @passwd_check;
  if ($option{'u'}) {
    if (-e "$sudoers.prersa") {
      print "Restoring $sudoers\n";
      copy("$sudoers.prersa",$sudoers);
      unlink("$sudoers.prersa");
    }
  }
  elsif (-e $sudoers) {
    @sudoers_info = read_file($sudoers);
    @passwd_check = grep { /\%\Q$admin_group\E/ && /NOPASSWD/ && !/^#/ } @sudoers_info;
    if (@passwd_check) {
      print "File $sudoers contains a NOPASSWD entry\n";
      # If running in fix mode take a copy of sudoers and fix NOPASSWD
      if ($option{'f'}) {
        print "Fixing $sudoers\n";
        if (!-e "$sudoers.prersa") {
          copy($sudoers,"$sudoers.prersa");
          chmod((stat($sudoers))[2] & 07777,"$sudoers.prersa");
        }
        foreach my $line (@sudoers_info) {
          $line =~ s/NOPASSWD/PASSWD/g;
        }
        write_file($sudoers,">",@sudoers_info);
      }
    }
  }
  else {
    print "File $sudoers requires a password to escalate privileges\n";
  }
  return;
}

# Subroutine to check /etc/group has a entry for the admin/wheel group

sub etc_group_check {
  my $group_file = "/etc/group";
  my @group_check;
  my $members;
  @group_check = grep { /^\Q$admin_group\E/ } read_file($group_file);
  if (!@group_check) {
    print "File $group_file does not contain a $admin_group group entry\n";
    return;
  }
  chomp($group_check[0]);
  $members = (split(/:/,$group_check[0]))[3];
  if (!defined($members) || $members !~ /\w/) {
    print "File $group_file has no members in $admin_group\n";
  }
  else {
    print "File $group_file contains a $admin_group group with members\n";
    if ($option{'f'}) {
      sudo_passwd_check(get_sudoers());
    }
  }
  return;
}

# Main check subroutine

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
# This is required as different Solaris packages install in different places

sub get_sudoers {
  my $etc_dir;
  my $sudoetc;
  foreach $etc_dir (@etc_dirs) {
    $sudoetc = "$etc_dir/sudoers";
    if (-e $sudoetc) {
      if ($option{'c'}) {
        print "Sudoers file found at $sudoetc\n";
      }
      return($sudoetc);
    }
  }
  return("");
}

# Subroutine to find location of sudo
# This is required as different Solaris packages install in different places

sub get_sudo_bin {
  my $bin_dir;
  my $sudo_bin;
  foreach $bin_dir (@bin_dirs) {
    $sudo_bin = "$bin_dir/sudo";
    if (-e $sudo_bin) {
      if ($option{'c'}) {
        print "Sudo found at $sudo_bin\n";
      }
      return($sudo_bin);
    }
  }
  return("");
}

# Subroutine to clean up

sub install_clean_up {
  my $path;
  foreach $path (glob("$tmp_dir/PAM*")) {
    if (-d $path) {
      remove_tree($path);
    }
    else {
      unlink($path);
    }
  }
  return;
}

# .tar.gz gets embedded after this

__DATA__
