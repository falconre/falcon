#-*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box = "generic/debian9"  # Stretch
  #config.vm.box = "ubuntu/bionic64"  # 18.04

  config.vm.provision "file", source: "dependencies.sh", destination: "$HOME/dependencies.sh"
  config.vm.provision "shell", path: "setup.sh", privileged: false
end

