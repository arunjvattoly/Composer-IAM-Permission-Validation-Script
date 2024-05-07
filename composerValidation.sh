#!/bin/bash
#title           :composerValidation.sh
#description     :This script will validate composer IAM permissions without requiring an environment in failed state
#owner           :mgtca
#contributor     :arunjvattoly, mgtca
#version         :1.1 | Arun  | Dec 07 2021 | Initial commit to verify composer 1 & 2 IAM permissions
#                :1.2 | Marco | Aug 23 2022 | Implemented validations for non existing composer instance
#                :1.3 | Marco | Feb 22 2023 | Add CMEK validations;
#                                             Remove `Service Account User` requirement
#                :1.4 | Marco | Jul 13 2023 | Allow possibility of v2 ext. role to be set at the env. SA level
#                                             Allow possibility of CMEK permissions given at key level
#==============================================================================
#color theme
red=$'\e[31m'
green=$'\e[32m'
yellow=$'\e[33m'
blue=$'\e[34m'
nc=$'\e[0m'
bold=$(tput bold)
normal=$(tput sgr0)

project_id=$(gcloud config list core/project --format='value(core.project)')

#### Service or host ####
echo "${bold}Please confirm project id '$project_id' is...${normal}"
PS3="Please enter your numeric choice: "
select project_type in "composer project" "network host project"; do
  if [[ -z "$project_type" ]]; then
    echo "Invalid selection"
  else
    echo "You have have confirmed project id: $project_id as $project_type"
    if [[ $REPLY == "1" ]]; then
      env='SERVICE'
    else
      env='HOST'
    fi
    break
  fi
done
echo

#### Obtaining necessary values ####
echo -n "${bold}Composer instance location (e.g. us-central1)${normal}: "
IFS= read -r location
echo

echo -n "${bold}Env. Subnet in form 'projects/<project-id>/regions/<region>/subnetworks/<subnet-id>' (just Enter for default subnet in region $location)${normal}: "
IFS= read -r subnetwork
subnetwork=${subnetwork:-"projects/$project_id/regions/$location/subnetworks/default"}
echo


if [[ $env = 'SERVICE' ]]; then
  #### Necessary values if in service project ####
  echo -n "${bold}CMEK Key in the form 'projects/<project-id>/locations/<location>/keyRings/<key-ring>/cryptoKeys/<key-name>' (just Enter to skip)${normal}: "
  IFS= read -r kms_key
  kms_key=${kms_key:-False}
  echo

  if [[ $kms_key != False ]]; then
    key_name=$(echo "$kms_key" | awk -F'/' '{print $8}')
    key_ring=$(echo "$kms_key" | awk -F'/' '{print $6}')
    key_location=$(echo "$kms_key" | awk -F'/' '{print $4}')
    if [[ "${key_location}" != "${location}" ]]; then
      echo "${bold}${red}WATCH OUT!${nc} The key location is not the same as the env. location!"
      echo "See https://cloud.google.com/composer/docs/composer-2/configure-cmek-encryption#before_you_begin"
      echo "You must create a CMEK key in the same region where your environments are located. You cannot use multi-regional or global keys.${normal}"
      echo
    fi
  fi

  project_number=$(gcloud projects describe "$project_id" --format="value(projectNumber)")

  default_sa=$project_number-compute@developer.gserviceaccount.com
  echo -n "${bold}Environment service account, press Enter for default service account $default_sa${normal}: "
  IFS= read -r service_account
  service_account=${service_account:-$default_sa}

  echo -n "${bold}Composer Version (1 or 2) press Enter for default 2${normal}: "
  IFS= read -r version
  version=${version:-2}
  host_project_id=$(echo "$subnetwork" | awk -F'/' '{print $2}')
  if [[ $project_id != "$host_project_id" ]]; then
    is_sharedVPC='True'
  else
    is_sharedVPC='False'
  fi
  echo

  #### Composer Instance Details ####
  echo -e "${yellow}============ Composer Instance details =============="
  echo -e "Project ID: $project_id"
  echo -e "Project Number: $project_number"
  echo -e "location: $location"
  echo -e "Shared VPC: $is_sharedVPC"
  if [[ "$is_sharedVPC" == 'True' ]]; then
    echo -e "Shared VPC network: $subnetwork"
  fi
  echo -e "CMEK Enabled: ${kms_key}"
  echo -e "Composer version: $version"
  echo -e "=====================================================${nc}"
  echo

  #### Verifying if SA is from different project #####
  domain=$(echo "$service_account" | awk -F@ '{print $2}')
  service_account_project=$(echo "$domain" | awk -F. '{print $1}')
  if [[ $default_sa != "$service_account" && "$service_account_project" != "$project_id" ]]; then
    echo ------------Verifying if SA is from different project------------------
    echo "${red} Service account $service_account is created in project $service_account_project Please run the script on service account project to validate additional permissions ${nc} "
    echo "${yellow} Please refer to following documentation ${nc}"
    echo "https://cloud.google.com/composer/docs/how-to/access-control#using_a_service_account_from_another_project"
    echo ==============================================
    fi # end if SA is from different project

    echo "Composer Service Account: $service_account"
    echo "Need 'roles/composer.worker' but 'roles/editor' role also suffices"
    condition="roles/composer.worker|roles/editor"
    echo ------------configured roles------------------
    gcloud projects get-iam-policy "$project_id" \
      --flatten="bindings[].members" \
      --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:$service_account" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

    echo ==============================================
    echo

    #### Checking Composer Agent Service Account ####
    echo "Composer Agent Service Account: service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
    echo "Need 'roles/composer.serviceAgent'"
    condition="roles/composer.serviceAgent"
    if [[ $version == 2 ]]; then
      echo "Need 'roles/composer.ServiceAgentV2Ext' ( Cloud Composer v2 API Service Agent Extension) for Composer 2 instances"
      condition="roles/composer.serviceAgent|roles/composer.ServiceAgentV2Ext"
    fi
    echo ------------configured roles------------------
    gcloud projects get-iam-policy "$project_number" \
      --flatten="bindings[].members" \
      --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

    echo ==============================================
    echo

    if [[ $version == 2 ]]; then
      echo "${yellow}NOTE${nc}: Creation also works if v2 ext. role is only granted at the environment service account-level"
      echo "Checking roles granted to 'service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com'at the level of '$service_account'..."
      echo ------------configured roles------------------
      gcloud iam service-accounts get-iam-policy "$service_account" \
        --flatten="bindings[].members" \
        --format='table[box,no-heading](bindings.role)' \
        --filter="bindings.members:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $"roles/composer.ServiceAgentV2Ext"'|$'
    fi
    echo

    #### Cloud Build Service Account ####
    echo "Cloud build service account: $project_number@cloudbuild.gserviceaccount.com"
    echo "Need 'roles/cloudbuild.builds.builder'"
    condition="roles/cloudbuild.builds.builder"
    echo ------------configured roles------------------
    gcloud projects get-iam-policy "$project_id" \
      --flatten="bindings[].members" \
      --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:$project_number@cloudbuild.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

    echo ==============================================
    echo

    #### Editor ####
    echo "Google APIs service account: $project_number@cloudservices.gserviceaccount.com"
    echo "Need 'roles/editor'"
    condition="roles/editor"
    echo ------------configured roles------------------
    gcloud projects get-iam-policy "$project_id" \
      --flatten="bindings[].members" \
      --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:$project_number@cloudservices.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

    echo ==============================================
    echo

    #### CMEK Validation ####
    if [[ "$kms_key" != False ]]; then
      echo "CMEK role can be configured at ${yellow}PROJECT-LEVEL${nc} or ${blue}KEY-LEVEL${nc}"
      echo 
      echo "Checking CMEK at ${blue}KEY-LEVEL${nc} for key '$kms_key'"
      echo

      echo "Need 'serviceAccount:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com'"
      condition="serviceAccount:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"

      echo "Need 'serviceAccount:service-$project_number@compute-system.iam.gserviceaccount.com'"
      condition="${condition}|serviceAccount:service-$project_number@compute-system.iam.gserviceaccount.com"

      echo "Need 'serviceAccount:service-$project_number@container-engine-robot.iam.gserviceaccount.com'"
      condition="${condition}|serviceAccount:service-$project_number@container-engine-robot.iam.gserviceaccount.com"

      echo "Need 'serviceAccount:service-$project_number@gcp-sa-artifactregistry.iam.gserviceaccount.com'"
      condition="${condition}|serviceAccount:service-$project_number@gcp-sa-artifactregistry.iam.gserviceaccount.com"

      echo "Need 'serviceAccount:service-$project_number@gcp-sa-pubsub.iam.gserviceaccount.com'"
      condition="${condition}|serviceAccount:service-$project_number@gcp-sa-pubsub.iam.gserviceaccount.com"

      echo "Need 'serviceAccount:service-$project_number@gs-project-accounts.iam.gserviceaccount.com'"
      condition="${condition}|serviceAccount:service-$project_number@gs-project-accounts.iam.gserviceaccount.com"

      echo
      echo "Service accounts with 'roles/cloudkms.cryptoKeyEncrypterDecrypter' are..."

      echo ------------configured roles------------------
      gcloud kms keys get-iam-policy "$key_name" --keyring="$key_ring" --location="$key_location" \
        --flatten="bindings[].members" \
        --format='table[box,no-heading](bindings.members)' \
        --filter="bindings.role:roles/cloudkms.cryptoKeyEncrypterDecrypter" | GREP_COLOR='01;32' egrep --color -E "$condition"'|$'

      echo ==============================================
      echo

      echo "Checking CMEK at ${yellow}PROJECT-LEVEL${nc}..."
      echo 

      echo "Cloud Composer Service Agent: service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
      echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
      condition="roles/cloudkms.cryptoKeyEncrypterDecrypter"
      echo ------------configured roles------------------
      gcloud projects get-iam-policy "$project_id" \
        --flatten="bindings[].members" \
        --format='table[box,no-heading](bindings.role)' \
        --filter="bindings.members:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

      echo ==============================================
      echo

      echo "Artifact Registry Service Agent: service-$project_number@gcp-sa-artifactregistry.iam.gserviceaccount.com"
      echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
      echo ------------configured roles------------------
      gcloud projects get-iam-policy "$project_id" \
        --flatten="bindings[].members" \
        --format='table[box,no-heading](bindings.role)' \
        --filter="bindings.members:service-$project_number@gcp-sa-artifactregistry.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

      echo ==============================================
      echo

      echo "GKE Service Agent: service-$project_number@container-engine-robot.iam.gserviceaccount.com"
      echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
      echo ------------configured roles------------------
      gcloud projects get-iam-policy "$project_id" \
        --flatten="bindings[].members" \
        --format='table[box,no-heading](bindings.role)' \
        --filter="bindings.members:service-$project_number@container-engine-robot.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

      echo ==============================================
      echo
      echo "Pub/Sub Service Agent: service-$project_number@gcp-sa-pubsub.iam.gserviceaccount.com"
      echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
      echo ------------configured roles------------------
      gcloud projects get-iam-policy "$project_id" \
        --flatten="bindings[].members" \
        --format='table[box,no-heading](bindings.role)' \
        --filter="bindings.members:service-$project_number@gcp-sa-pubsub.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

      echo ==============================================
      echo
      echo "Compute Engine Service Agent: service-$project_number@compute-system.iam.gserviceaccount.com"
      echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
      echo ------------configured roles------------------
      gcloud projects get-iam-policy "$project_id" \
        --flatten="bindings[].members" \
        --format='table[box,no-heading](bindings.role)' \
        --filter="bindings.members:service-$project_number@compute-system.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'

      echo ==============================================
      echo
      echo "Cloud Storage Service Agent: service-$project_number@gs-project-accounts.iam.gserviceaccount.com"
      echo "Need 'Cloud KMS CryptoKey Encrypter/Decrypter'"
      echo ------------configured roles------------------
      gcloud projects get-iam-policy "$project_id"  \
        --flatten="bindings[].members" \
        --format='table[box,no-heading](bindings.role)' \
        --filter="bindings.members:service-$project_number@gs-project-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
              echo ==============================================
    fi # end CMEK validation
    echo

    #### ORG Policy Violations ####
    echo "ORG Policy Violations ..."
    echo "- compute.disableSerialPortLogging"
    echo "- compute.requireOsLogin"
    echo "- compute.vmCanIpForward"
    echo "- compute.requireShieldedVm"
    echo "- compute.vmExternalIpAccess"
    echo "- compute.restrictVpcPeering"
    result=$(gcloud logging read "$(
        cat <<'FILTER'
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

    #### GCE QUOTA aka. Managed Instance Group Quota #####
    echo "Managed Instance Group Quota ..."
    result=$(gcloud logging read "$(
        cat <<'FILTER'
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

    if [[ "$is_sharedVPC" == 'True' ]]; then
        echo -e "${yellow} Since this is a shared VPC network please run this script again after logging into network host project: $host_project_id ${nc}"
        echo
    fi

    fi # end if for service project


    if [[ $env = 'HOST' ]]; then # if this is the network host project

      echo -n "Service Project Number (project number of project where composer env. will live): "
      IFS= read -r project_number
      host_project_id=$(gcloud config list core/project --format='value(core.project)')
      host_project_number=$(gcloud projects describe "$project_id" --format="value(projectNumber)")
      echo ==============================================
      echo

    #### Checking Google APIs service account #####
    echo "Google APIs service account: $project_number@cloudservices.gserviceaccount.com"
    echo "Need 'roles/compute.networkUser' in the host project (PROJECT LEVEL)"
    condition="roles/compute.networkUser"
    echo ------------configured roles------------------
    gcloud projects get-iam-policy "$host_project_id" \
      --flatten="bindings[].members" \
      --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:$project_number@cloudservices.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
          echo ==============================================
          echo

    #### Checking service project GKE service account at project level ####
    echo "Service project GKE service account: service-$project_number@container-engine-robot.iam.gserviceaccount.com"
    echo "Need 'roles/container.hostServiceAgentUser' in the host project"
    echo "Need 'compute.networkUser' at project / subnet level"
    condition="roles/compute.networkUser|roles/container.hostServiceAgentUser"
    echo ----configured roles at project level --------
    gcloud projects get-iam-policy "$host_project_id" \
      --flatten="bindings[].members" \
      --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:service-$project_number@container-engine-robot.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
          echo -----configured roles at subnet level --------

    #### Checking GKE service account at subnet level ####
    condition="roles/compute.networkUser"
    gcloud compute networks subnets get-iam-policy "$subnetwork" --region "$location" \
      --project "$host_project_id" --flatten='bindings[].members' --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:service-$project_number@container-engine-robot.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
          echo ==============================================
          echo

    #### Checking host project GKE service account at project level ####
    echo "Host project GKE service account: service-$host_project_number@container-engine-robot.iam.gserviceaccount.com"
    echo "Need 'container.serviceAgent' in the host project"
    condition="roles/container.serviceAgent"
    echo ----configured roles at project level --------
    gcloud projects get-iam-policy "$host_project_id" \
      --flatten="bindings[].members" \
      --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:service-$host_project_number@container-engine-robot.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
          echo ==============================================
          echo

    #### Checking Composer Agent Service Account ####
    echo "Composer Agent Service Account at project level: service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
    echo "Need 'roles/composer.sharedVpcAgent' for Private Instance"
    echo "Need 'roles/compute.networkUser' for Public Instance"
    condition="roles/composer.sharedVpcAgent|roles/compute.networkUser"
    echo ------------configured roles------------------
    gcloud projects get-iam-policy "$host_project_id" \
      --flatten="bindings[].members" \
      --format='table[box,no-heading](bindings.role)' \
      --filter="bindings.members:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" | GREP_COLOR='01;32' egrep --color -E $condition'|$'
          echo ==============================================
          echo
    fi # end if for network host project
