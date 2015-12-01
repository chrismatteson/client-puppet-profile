# services.rb

Facter.add(:services) do
  confine :kernel => 'Linux'
  setcode do
    services = Facter::Core::Execution.exec('service --status-all | sed "s/^........//" | tr "\n" ","')
    services_array = services.split(',')
    services_array
  end
end
