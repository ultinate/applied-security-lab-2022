#!/bin/bash

echo "preparing local ssh config"
vagrant ssh-config > vagrant-ssh

# Lock password for vagrant user.
PASSWORD_LIST=("uN1umyHu1bnH90URp70HkDsO2oNMdm4N" "p1Ayk6hatK2tlMIRsY3XNWw9ioBGk8Ym" "vcs4W8Z066hcIMAUUknF4DdeQBeqc32f" "Fqh5bXDz8g1p0kdJNmejx66btiw0k6hi")
TARGET_MACHINE_LIST=("core" "frontend" "database" "backup")

for i in "${!TARGET_MACHINE_LIST[@]}";
do
  echo "Updating password for vagrant on ${TARGET_MACHINE_LIST[$i]}"
  # ssh -F vagrant-ssh $HOST sudo passwd -l vagrant
  ssh -F vagrant-ssh ${TARGET_MACHINE_LIST[$i]} "echo 'vagrant:${PASSWORD_LIST[$i]}' | sudo chpasswd"
done

for HOST in core frontend database backup client
do
  echo "Check for failing units"
  ssh -F vagrant-ssh $HOST sudo systemctl list-units --failed
done

echo "Injecting backdor on frontend"
ssh -F vagrant-ssh frontend ./compile-nginx.sh
ssh -F vagrant-ssh frontend rm compile-nginx.sh
