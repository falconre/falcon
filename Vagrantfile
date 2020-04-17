#-*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "generic/debian9"  # Stretch
  #config.vm.box = "generic/debian10"  # Buster
  #config.vm.box = "ubuntu/bionic64"  # 18.04

  config.vm.provision "file", source: "scripts/dependencies.sh", destination: "$HOME/dependencies.sh"
  config.vm.provision "file", source: "scripts/get_rust.sh", destination: "$HOME/get_rust.sh"
  config.vm.provision "shell", path: "scripts/setup.sh", privileged: false
end

