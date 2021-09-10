Vagrant.configure("2") do |config|
  config.vm.box = "centos/7"
  config.vm.network "public_network", bridge: "wlp0s20f3"
  config.vm.hostname = "mrcp"
  config.vm.synced_folder ".", "/vagrant", type: "virtualbox"

  config.vm.provider "virtualbox" do |vb|
    vb.cpus = 3
    vb.memory = "4096"
  end

  config.vm.provision "ansible" do |ansible|
    ansible.playbook = "provisioning/playbook.yml"
  end
end
