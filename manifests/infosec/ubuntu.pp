class profile::infosec::ubuntu (
  $checkdirectories = {'/tmp'           => 'nodev,nosuid,noexec',
                       '/var'           => undef,
                       '/var/log'       => undef,
                       '/var/log/audit' => undef,
                       '/home'          => 'nodev',
                      },
  $disablefsmodules = ['cramfs','freevxfs','jffs','hfs','hfsplus','squashfs','udf'],
) {

# (1) Patching and Software Updates

#  exec {

# (2) File System Configuration

  $checkdirectories[$key].each |String $directory| {
    if $::partitions["$directory"] {
      notify { "$directory exists":
        message => "The $directory directory does have an entry in fstab.  This does not confirm if it's mounted correctly however",
      }
      mount "$directory" {
        ensure  => 'present',
        options => "$checkdirectories[$directory]",
      }
    }
    else {
      notify { "$directory does not exist":
        message => "The $directory directory does not have an entry in fstab.",
      }
    }
  }

  $disablefsmodule.each |String $module| {
    file_line { "$module":
      path   => '/etc/modprobe.d/blacklist',
      line   => "blacklist $module",
      notify => Service['udev'],
    }
    service { 'udev':
      ensure => 'running',
    }
  }

  service { 'autofs':
    ensure => 'stopped',
    enable => 'false',
  }

# (3) Secure Boot Settings

  file { '/boot/grub/grub.conf':
    ensure      => 'file',
    owner       => 'root',
    group       => 'root',
    permissions => 0600,
  }

# (4) Additional Process Hardening

  file_line { 'Core Dump Limits':
    path  => '/etc/security/limits.conf',
    line  => '* hard core 0',
    match => '* hard core',
  }

  file_line { 'Core Dump Config':
    path  => '/etc/sysctl.conf',
    line  => 'fs.suid_dumpable = 0',
    match => 'fs.suid_dumpable = ',
  }

  file_line { 'Randomize VA Space':
    path  => '/etc/sysctl.conf',
    line  => 'kernel.randomize_va_space = 2',
    match => 'kernel.randomize_va_space = ',
  }

#  Not clear that prelink will be installed at all?
#  exec { 'disable prelink':
#    command => '/usr/sbin/prelink -ua',
#    unless  => '/usr/sbin/prelink'
#  }

  service { 'apparmor':
    ensure => 'running',
    enable => true,
  }

# (5) OS Services

}

