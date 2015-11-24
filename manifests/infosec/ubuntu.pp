class profile::infosec::ubuntu (
  $checkdirectories = {'/tmp'           => 'nodev,nosuid,noexec',
                       '/var'           => undef,
                       '/var/log'       => undef,
                       '/var/log/audit' => undef,
                       '/home'          => 'nodev',
                      },
  $disablemodules = ['cramfs','freevxfs','jffs','hfs','hfsplus','squashfs','udf','dccp','sctp','rds','tipc'],
  $disableservices = ['nis,rsh-redone-client,talk,telnet,tftp,xinetd,chargen,daytime,echo,discard,time'],
  $networksettings = {'net.ipv4.ip_forward'                        => 0,
                      'net.ipv4.conf.all.send_requests'            => 0,
                      'net.ipv4.conf.default.send_requests'        => 0,
                      'net.ipv4.conf.all.accept_source_route'      => 0,
                      'net.ipv4.conf.default_accept_source_route'  => 0,
                      'net.ipv4.conf.all.accept_redirects'         => 0,
                      'net.ipv4.conf.default.accept_redirects'     => 0,
                      'net.ipv4.conf.all.secure_redirects'         => 0,
                      'net.ipv4.conf.default.secure_redirects'     => 0,
                      'net.ipv4.conf.all.log_martians'             => 1,
                      'net.ipv4.conf.default.log_martians'         => 1,
                      'net.ipv4.icmp_echo_ignore_broadcasts'       => 1,
                      'net.ipv4.icmp_ignore_bogus_error_responses' => 1,
                      'net.ipv4.conf.all.rp_filter'                => 1,
                      'net.ipv4.conf.default.rp_filter'            => 1,
                      'net.ipv4.tcp_syncookies'                    => 1,
                      'net.ipv6.conf.all.accept_ra'                => 0,
                      'net.ipv6.conf.default.accept_ra'            => 0,
                      'net.ipv6.conf.all.accept_redirects'         => 0,
                      'net.ipv6.conf.default.accept_redirects'     => 0,
                      'net.ipv6.conf.all.disable_ipv6'             => 1,
                      'net.ipv6.conf.default.disable_ipv6'         => 1,
                      'net.ipv6.conf.lo.disable_ipv6'              => 1,
                    },
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
    ensure => 'file',
    owner  => 'root',
    group  => 'root',
    mode   => 600,
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

  $disableservices.each |String $service| {
     service { "$service":
       ensure => 'stopped',
       enable => false,
     }

     package { "$service":
       ensure => 'absent',
     }
  }

# (6) Special Purpose Services

# Solved removing extra packages using Hiera with $disableservices variable

# Need to add hiera entries for this to meet compliance requirements, or enter
# here and have to manage idempotence
  include ntp

  file_line { 'Local Mail Only':
    line  => 'inet_interfaces = localhost',
    path  => '/etc/postfix/conf.cf',
    match => 'inet_interfaces = ',
  }

# (7) Network Configuration and Firewalls

  $networksettings[$key].each |String $setting| {
    file_line { '$setting':
      path   => '/etc/sysctl.conf',
      line   => "$setting = $networksettings[$setting],
      match  => '^$setting = [01]',
    }
  }

  package { 'tcpd':
    ensure => 'present',
  }

  file { ['/etc/hosts.allow','/etc/hosts.deny']:
    ensure => 'file',
    mode   => 644,
  }

# 7.4 is handled by the disable modules loop

  include networkmanager #Might not want this?
# Need to find a way to run 'nmcli nm wifi off'.  Maybe with an exec?

  include firewall

# (8) Logging and Auditing



}

