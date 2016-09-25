class event_collector {
  exec { 'add reddit ppa':
    command => 'add-apt-repository -y ppa:reddit/ppa',
    unless  => 'apt-cache policy | grep reddit/ppa',
    notify  => Exec['update apt cache'],
  }

  $dependencies = [
    'python',
    'python-baseplate',
    'python-coverage',
    'python-gevent',
    'python-kafka',
    'python-mock',
    'python-nose',
    'python-pyramid',
    'python-setuptools',
  ]

  package { $dependencies:
    ensure => installed,
    before => Exec['install app'],
  }

  exec { 'install app':
    user    => $::user,
    cwd     => $::project_path,
    command => 'python setup.py develop --user',
  }
}
