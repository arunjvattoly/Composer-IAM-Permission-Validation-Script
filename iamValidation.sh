#!/bin/bash
#title           :iamValidation.sh
#description     :This script will validate composer IAM permissions.
#owner           :arunjvattoly
#contributor     :arunjvattoly ,
#date            :Dec 07, 2021
#version         :0.2 | 22-Feb-2022
#==============================================================================
#color theme
red=$'\e[31m'
green=$'\e[32m'
yellow=$'\e[33m'
blue=$'\e[34m'
nc=$'\e[0m'

project_id=$(gcloud config list core/project --format='value(core.project)')
echo
echo "Please confirm project id: $project_id is : "
PS3="Please enter your numeric choice: "
select project_type in "composer project" "network host project";
do
    if [ -z "$project_type" ]; then
        echo "Invalid selection"
    else
        echo "You have have confirmed project id: $project_id as $project_type"
        if [ $REPLY == "1" ]; then
            env='SERVICE'
        else
            env='HOST'
        fi
        break
    fi
done
echo
read -p 'Enter location of the composer instance (eg: us-central1): ' location
if [[ $env = 'SERVICE' ]]; then
echo
echo "Select composer instance to troubleshoot"
select composer_instance in $(gcloud composer environments list --locations=$location --format='value(name)');
do
    if [ -z "$composer_instance" ]; then
        echo "Invalid selection"
    else
        echo "You have selected composer instance: $composer_instance"
        break
    fi
done
service_account=$(gcloud composer environments describe \
    $composer_instance \
    --location $location --format="value(config.nodeConfig.serviceAccount)")
project_number=$(gcloud projects describe $project_id --format="value(projectNumber)")
default_sa=$project_number-compute@developer.gserviceaccount.com
is_private=$(gcloud composer environments describe \
    $composer_instance \
    --location $location --format="value(config.privateEnvironmentConfig.enablePrivateEnvironment)")
version=$(gcloud composer environments describe \
    $composer_instance \
    --location $location --format="value(config.softwareConfig.imageVersion)")
subnetwork=$(gcloud composer environments describe \
    $composer_instance \
    --location $location --format="value(config.nodeConfig.subnetwork)")
host_project_id=$(echo $subnetwork | awk -F'/' '{print $2}')
if [ "$project_id" != "$host_project_id" ]; then
    is_sharedVPC='True'
else
    is_sharedVPC='False'
fi
kms_key=$(gcloud composer environments describe \
    $composer_instance \
    --location $location --format="value(config.encryptionConfig.kmsKeyName)")
 if [ -z "$kms_key" ]; then
    is_cmek_encrypted='False'
 else
    is_cmek_encrypted='True'
 fi
echo
echo -e "${yellow}============ Composer Instance details =============="
echo -e "Project ID: $project_id"
echo -e "Project Number: $project_number"
echo -e "Composer Instance: $composer_instance"
echo -e "location: $location"
echo -e "Shared VPC: $is_sharedVPC"
if [ "$is_sharedVPC" == 'True' ];then
echo -e "Shared VPC network: $subnetwork"
fi
echo -e "Is Private: ${is_private:-False}"
echo -e "CMEK Enabled: ${is_cmek_encrypted}"
echo -e "Composer version: $version"
echo -e "=====================================================${nc}"
echo
#### Verifying if SA is from different project #####
domain=`echo "$service_account" | awk -F@ '{print $2}'`
service_account_project=`echo "$domain" | awk -F. '{print $1}'`
if [[ $default_sa != $service_account && "$service_account_project" != "$project_id" ]]; then
    echo
    echo ------------Verifying if SA is from different project------------------
    echo "${red} Service account $service_account is created in project $service_account_project Please run the script on service account project to validate additional permissions ${nc} "
    echo "${yellow} Please refer to following documentation" ${nc}
    echo "https://cloud.google.com/composer/docs/how-to/access-control#using_a_service_account_from_another_project"
    echo ===========================================================================
    echo
fi
echo "Composer Service Account: $service_account"
if [ $default_sa == $service_account ];then
    echo "Need 'roles/editor' to default service account"
    condition="roles/editor"
else
    if [ "$is_private" == 'True' && $version == composer-2* ];then
        echo "Need 'roles/composer.worker' for PRIVATE IP instance"
        condition="roles/composer.worker"
    elif [ "$is_private" == 'True' ];then
        echo "Need 'roles/composer.worker' and 'roles/iam.serviceAccountUser' for PRIVATE IP instance"
        condition="roles/composer.worker|roles/iam.serviceAccountUser"
    else
        echo "Need 'roles/composer.worker' for PUBLIC IP instance"
        condition="roles/composer.worker"
    fi
fi
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:$service_account"  | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
#Checking Composer Agent Service Account
echo "Composer Agent Service Account: service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
echo "Need 'roles/composer.serviceAgent'"
condition="roles/composer.serviceAgent"
if [[ $version == composer-2* ]];then
echo "Need 'roles/composer.ServiceAgentV2Ext' ( Cloud Composer v2 API Service Agent Extension) for Composer 2 instances"
condition="roles/composer.serviceAgent|roles/composer.ServiceAgentV2Ext"
fi
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_number  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
#Cloud Build Service Account
echo "Cloud build service account: $project_number@cloudbuild.gserviceaccount.com"
echo "Need 'roles/cloudbuild.builds.builder'"
condition="roles/cloudbuild.builds.builder"
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:$project_number@cloudbuild.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
#Compute Network User
#Editor
echo "Google APIs service account: $project_number@cloudservices.gserviceaccount.com"
echo "Need 'roles/editor'"
condition="roles/editor"
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:$project_number@cloudservices.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
#CMEK Validation
#Cloud KMS CryptoKey Encrypter/Decrypter
if [[ "$is_cmek_encrypted" == 'True' ]];then
echo "Cloud Composer Service Agent: service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
condition="roles/cloudkms.cryptoKeyEncrypterDecrypter"
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
echo "Artifact Registry Service Agent: service-$project_number@gcp-sa-artifactregistry.iam.gserviceaccount.com"
echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@gcp-sa-artifactregistry.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
echo "GKE Service Agent: service-$project_number@container-engine-robot.iam.gserviceaccount.com"
echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@container-engine-robot.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
echo "Pub/Sub Service Agent: service-$project_number@gcp-sa-pubsub.iam.gserviceaccount.com"
echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@gcp-sa-pubsub.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
echo "Compute Engine Service Agent: service-$project_number@compute-system.iam.gserviceaccount.com"
echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@compute-system.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
echo "Cloud Storage Service Agent: service-$project_number@gs-project-accounts.iam.gserviceaccount.com"
echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
echo ------------configured roles------------------
gcloud projects get-iam-policy $project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@gs-project-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
fi
echo
#ORG Policy Violations
echo "ORG Policy Violations ..."
echo "compute.disableSerialPortLogging, compute.requireOsLogin, compute.vmCanIpForward, compute.requireShieldedVm, compute.vmExternalIpAccess , compute.restrictVpcPeering"
result=$(gcloud logging read "$(cat <<'FILTER'
protoPayload.status.message=~"Constraint .* violated"
("compute.disableSerialPortLogging" OR "compute.requireOsLogin" OR "compute.vmCanIpForward" OR "compute.requireShieldedVm"
 OR "constraints/compute.vmExternalIpAccess" OR "compute.restrictVpcPeering")
protoPayload.@type="type.googleapis.com/google.cloud.audit.AuditLog"
severity=ERROR
FILTER
)" --limit=5 --format "value(protoPayload)")
echo ------------configured roles------------------
if [[ $result ]]; then
    echo -e "${red}Org Policy Violation detected${nc}"
else
    echo -e "${green}No Org Policy Violation detected${nc}"
fi
echo ==============================================
echo
#GCE QUOTA
echo "Managed Instance Group Quota ..."
result=$(gcloud logging read "$(cat <<'FILTER'
jsonPayload.message:"googleapi: Error 403: Insufficient regional quota to satisfy request:"
severity>=WARNING
FILTER
)" --limit=5 --format "value(jsonPayload.message)")
echo ------------configured roles------------------
if [[ $result ]]; then
    echo -e "${red}Managed Instance Group Quota Exceeded${nc}"
else
    echo -e "${green}Managed Instance Group Quota within limits${nc}"
fi
echo ==============================================
echo


echo ==============================================
if [ "$is_private" == 'True' ];then
echo "Network details"
echo ------------configured roles------------------
gcloud composer environments describe \
    $composer_instance \
    --location $location --format="table(config.privateEnvironmentConfig)"
echo ==============================================
echo
fi
if [ "$is_sharedVPC" == 'True' ];then
echo -e "${yellow} Since this is a shared VPC network please run this script again after logging into network host project: $host_project_id ${nc}"
echo
fi
else
read -p 'SUBNET: ' SUBNET
read -p 'COMPOSER PROJECT NUMBER: ' project_number
host_project_id=$(gcloud config list core/project --format='value(core.project)')
host_project_number=$(gcloud projects describe $project_id --format="value(projectNumber)")
echo ==============================================
echo
#Checking Google APIs service account
echo "Google APIs service account: $project_number@cloudservices.gserviceaccount.com"
echo "Need 'roles/compute.networkUser' in the host project (PROJECT LEVEL)"
condition="roles/compute.networkUser"
echo ------------configured roles------------------
gcloud projects get-iam-policy $host_project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:$project_number@cloudservices.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
#Checking service project GKE service account at project level
echo "Service project GKE service account: service-$project_number@container-engine-robot.iam.gserviceaccount.com"
echo "Need 'roles/container.hostServiceAgentUser' in the host project"
echo "Need 'compute.networkUser' at project / subnet level"
condition="roles/compute.networkUser|roles/container.hostServiceAgentUser"
echo ----configured roles at project level --------
gcloud projects get-iam-policy $host_project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@container-engine-robot.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo -----configured roles at subnet level --------
#Checking GKE service account at subnet level
condition="roles/compute.networkUser"
gcloud compute networks subnets get-iam-policy $SUBNET --region $location  \
--project $host_project_id --flatten='bindings[].members' --format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@container-engine-robot.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
#Checking host project GKE service account at project level
echo "Host project GKE service account: service-$host_project_number@container-engine-robot.iam.gserviceaccount.com"
echo "Need 'container.serviceAgent' in the host project"
condition="roles/container.serviceAgent"
echo ----configured roles at project level --------
gcloud projects get-iam-policy $host_project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$host_project_number@container-engine-robot.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
#Checking Composer Agent Service Account
echo "Composer Agent Service Account at project level: service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
echo "Need 'roles/composer.sharedVpcAgent' for Private Instance"
echo "Need 'roles/compute.networkUser' for Public Instance"
condition="roles/composer.sharedVpcAgent|roles/compute.networkUser"
echo ------------configured roles------------------
gcloud projects get-iam-policy $host_project_id  \
--flatten="bindings[].members" \
--format='table[box,no-heading](bindings.role)' \
--filter="bindings.members:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
echo ==============================================
echo
fi
