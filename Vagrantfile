# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  
  config.vagrant.plugins = "vagrant-qemu"
  config.vm.box = "cloud-image/debian-12"
  config.vm.synced_folder ".", "/vagrant", disabled: true
  config.vm.boot_timeout = 120
  config.vm.graceful_halt_timeout = 30
  config.vm.hostname = "vagrant"

  config.trigger.before :up do |trigger|
    trigger.run = {inline: <<-SHELL
       bash -c '
        rm -f /tmp/nvme0.img /tmp/nvme1.img;
        qemu-img create -f raw /tmp/nvme0.img 20G;
        qemu-img create -f raw /tmp/nvme1.img 20G;
       '
      SHELL
    }
  end

  config.trigger.after :up do |trigger|
    trigger.run = {inline: <<-SHELL
      bash -c '
        echo "#####################";
        echo -n "== Connect to serial console ==";
        echo "socat - UNIX-CONNECT:$HOME/.vagrant.d/tmp/vagrant-qemu/$(cat .vagrant/machines/default/qemu/id)/qemu_socket_serial";
        echo "#####################";
      '
      SHELL
    }
  end

  config.vm.provider :qemu do |qe, override|
    qe.smp = 4
    qe.memory = 4096
    qe.ssh_port = 2222
    qe.ssh_host = "127.0.0.1"
    qe.drive_interface = "none"
    qe.extra_drive_args = "cache=none,aio=threads"
    
    # Add 2 NVMe drives (20GB each, ephemeral) with boot order: nvme0, nvme1, main disk
    qe.extra_qemu_args = %w(
      -drive file=/tmp/nvme0.img,if=none,id=nvme0,format=raw
      -device nvme,drive=nvme0,serial=nvme0,bootindex=1
      -drive file=/tmp/nvme1.img,if=none,id=nvme1,format=raw
      -device nvme,drive=nvme1,serial=nvme1,bootindex=2
      -object iothread,id=io1
      -device virtio-blk-pci,drive=disk0,iothread=io1,bootindex=3
      -device virtio-rng-device
    )
  end

  # Port forwarding
  config.vm.network "forwarded_port", guest: 443, host: 4443

  config.vm.provision "shell", inline: <<-SHELL
    sudo apt update
    sudo apt install -y mdadm gpg
    echo 'root:root' | sudo chpasswd
    sudo sed -i 's/PasswordAuthentication no/PasswordAuthentication yes/g' /etc/ssh/sshd_config
    sudo sed -i -e '$aPermitRootLogin yes' /etc/ssh/sshd_config
    sudo systemctl reload sshd.service
    sudo chsh -s /bin/bash vagrant
  SHELL

end
