class profile::infosec::ubuntu (
  $checkdirectories = {'/tmp'           => 'nodev,nosuid,noexec',
                       '/var'           => undef,
                       '/var/log'       => undef,
                       '/var/log/audit' => undef,
                       '/home'          => 'nodev',
                      },
  $disablefsmodules = ['cramfs','freevxfs','jffs','hfs','hfsplus','squashfs','udf'],
) {

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


}

