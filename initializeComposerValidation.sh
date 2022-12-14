#!/bin/bash
#title           :initializeComposerValidation.sh
#description     :This script will validate Composer issues.
#owner           :arunjvattoly
#contributor     :arunjvattoly ,
#date            :Dec 14, 2022
#version         :0.1
green=$'\e[32m'
nc=$'\e[0m'

echo "${green}Reinitializing git repo for checking latest updates.${nc}"
mkdir Composer && cd "$_" Composer
echo $pwd
#git init
#git clone https://github.com/arunjvattoly/Composer.git
#git checkout main -f
echo $(git log -n 1)
chmod +x ./iamValidation.sh 
./iamValidation.sh
