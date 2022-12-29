# Infrastructure 

## Install vagrant

1. Install vagrant: https://www.vagrantup.com/docs/installation
2. Optionally, run `vagrant autocomplete install`


## Set up the environment
1. Navigate to this folder `source/vagrant/secrets`
2. Run `bash generate_ssh_keys.sh`
3. Navigate to this folder `/source/core/secret`
4. Run `bash local_bootstrap_once.sh`
5. Navigate to this folder `cd source/vagrant`
6. Run `vagrant up`

>> Note: Run step 2 and 4 only once expect all VMs are deleted and new keys are required

This will spin up all components of the project using you local VirtualBox. For IPs and fully qualified domain names (FQDN), see `provision.sh` file.

* Client: This machine is the only one with VirtualBox UI.
  * Username: `vagrant`, password: `vagrant`.
* Frontend: Dual-homed, entrance point to the CA system, including a web-server, jump-host for administrators and the application logic. 
* Core CA:   A machine performing the holding the CA private keys that generates and manages certificates.
* Database
* Backup

Note a private network is configured on VirtualBox. the front end will have another NIC with "nat" so you can access it from your laptop

In this folder is the general provisioner script (general for all VMs). Inside `source/[vm_name]` folders, there are the provisioner scripts for a each VM. 

## Update your local setup.

If you already did vagrant up before and now you just want to update the latest changes you can simply do:

"vagrant up --provision"

this will run all the privision scripts again. it should take considerable less time than running from scratch.
If you are the one who did change thing here, please consider start over (cleanup):

## Start over ("cleanup")
1. Navigate to this folder `cd source/vagrant`
2. Run `vagrant destroy -f`
3. Start again as described above.

This will delete all your local VMs (keeping the boxes / "base images" in cache).


## SSH into a VM

For the final solution we will have to "jump" via the frontend. 

Vagrant creates a user vagrant and cofngures ssh with cert auth. It also creates a fresh cert and inserts it into the vm.

During dev time we can `vagrant ssh backup`.

If you want to direct ssh you can:

`vagrant ssh-config frontend >> ~/.ssh/config
ssh frontend`

## When infra changes (changes on Vagrantfile):

### Recreate a VM:

```
vagrant destroy client
vagrant provision client
```

### Restart vagrant

`vagrant reload`

### recreate all

```
vagrant destroy -f
vagrant up
```

### vagrant up in paralell

```
grep config.vm.define Vagrantfile | awk -F'"' '{print $2}' | xargs -P2 -I {} vagrant up {}
```

### provision all in paralell

```
grep config.vm.define Vagrantfile | awk -F'"' '{print $2}' | xargs -P2 -I {} vagrant provision {}
```
