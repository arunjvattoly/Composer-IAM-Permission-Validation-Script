#!/bin/bash
#title           :iamValidation.sh
#description     :This script will validate Cloud Composer IAM permissions.
#owner           :arunjvattoly
#date            :Dec 07, 2021
#version         :0.2 | 22-Feb-2022
#                :0.3 | 01-June-2024 (Added CMEK and support for validating non existing composer instances)
#==============================================================================
# Color Theme (Simplified)
red='\033[0;31m'
green='\033[0;32m'
yellow='\033[0;33m'
nc='\033[0m' # No Color

# Project and Environment Setup
project_id=$(gcloud config get-value project)
project_number=$(gcloud projects describe $project_id --format="value(projectNumber)")
default_sa=$project_number-compute@developer.gserviceaccount.com

echo "Current Project ID: $project_id"
# Project Type Selection
if [[ $# -eq 4 ]]; then #if all 3 args provided, no need to ask for customer / network project.
    project_type=2
else
    echo "Select Project Type:"
    echo "1) Composer Project"
    echo "2) Network Host Project"
    read -p "Enter your choice (1 or 2): " project_type
    project_type=${project_type:-1}
fi

# Function for highlighting IAM Permissions
highlight_roles() {
    local required_roles=$1
    local existing_roles=$2
    # Convert required_roles to an array if it's a string
    if [[ $required_roles == *"|"* ]]; then # Check for pipe separator
        IFS='|' read -ra required_roles <<<"$required_roles"
    else
        required_roles=("$required_roles") # Convert single role to array
    fi

    echo "Required Roles Status:"
    specific_role="roles/composer.ServiceAgentV2Ext"
    # Loop over the required roles and check for existence in a single line using grep
    for role in "${required_roles[@]}"; do
        if echo "$existing_roles" | grep -q "$role"; then
            echo -e "${green}$role (Found)${nc}"
        else
            has_missing_permissions=1
            if [[ "$role" != "$specific_role" ]]; then
                echo -e "${red}$role (Missing)${nc}"
            fi

        fi
    done
    if [[ $has_missing_permissions == 1 ]]; then
        echo ========================== Existing roles =================================
        printf "$existing_roles \n"
    fi
    echo ===========================================================================
}

# Function for Checking IAM Permissions
check_role() {
    local service_account=$1
    local required_roles=$2
    local check_level=${3:-"project"} # Default to "projeßct" level
    local binding_service_Account=$4
    local has_missing_permissions=0

    if [[ $check_level == "project" ]]; then
        # Fetch existing roles for the service account at the project level
        existing_roles=$(gcloud projects get-iam-policy $project_id \
            --flatten="bindings[].members" \
            --format='value(bindings.role)' \
            --filter="bindings.members:$service_account")
    elif [[ $check_level == "service-account" ]]; then
        # Fetch binding service account roles against a service account
        existing_roles=$(gcloud iam service-accounts get-iam-policy $service_account \
            --flatten="bindings[].members" \
            --format='value(bindings.role)' \
            --filter="bindings.members:$binding_service_Account")
    else
        echo "Invalid check level: $check_level. Please use 'project' or 'service-account'."
        return 1
    fi

    highlight_roles "$required_roles" "${existing_roles[@]}"

}

if [[ $project_type == 1 ]]; then

    while true; do
        read -p 'Enter Composer location (e.g., us-central1) or type "manual" to enter details manually: ' location

        if [[ $location == "manual" ]]; then
            # Retrieve Composer Instance details from user
            read -p 'Enter Composer instance location (e.g. us-central1): ' location
            read -p "Enter Subnet in form 'projects/<project-id>/regions/<region>/subnetworks/<subnet-id>, press Enter for default network: " subnetwork
            subnetwork=${subnetwork:-"projects/$project_id/regions/$location/subnetworks/default"}
            read -p 'Enter Service Account: ' service_account
            read -p "Enter Composer Version (1 or 2), press Enter for default 2: " version
            version=${version:-2}
            read -p 'Enter True for Private, press Enter for default True)' is_private
            is_private=${is_private:-True}
            read -p "Using CMEK Key ? Input in format 'projects/<project-id>/locations/<location>/keyRings/<key-ring>/cryptoKeys/<key-name>' (press Enter to skip): " kms_key
            kms_key=${kms_key}
            break # Exit the loop after manual input
        fi

        # Retrieve Composer Instance details from Composer API
        echo "Available Composer Instances:"
        instance_list=$(gcloud composer environments list --locations $location --format='value(name)')
        if [[ -z "$instance_list" ]]; then
            echo -e "${red}No Composer instances found in this location.${nc}"
        else
            echo "$instance_list" | nl -w1 -s') '
            read -p 'Select Composer instance (number): ' instance_index

            composer_instance=$(echo "$instance_list" | sed -n "${instance_index}p")
            if [[ -z "$composer_instance" ]]; then
                echo -e "${red}Invalid selection.${nc}"
            else
                composer_details=$(gcloud composer environments describe "$composer_instance" \
                    --location "$location" \
                    --format="value(config.nodeConfig.serviceAccount,config.privateEnvironmentConfig.enablePrivateEnvironment,config.softwareConfig.imageVersion,config.nodeConfig.subnetwork,config.encryptionConfig.kmsKeyName)")
                read service_account is_private version subnetwork kms_key <<<"$composer_details"
                break # Exit the loop if a valid instance is selected
            fi
        fi
    done

    host_project_id=$(echo $subnetwork | awk -F'/' '{print $2}')
    if [[ -n "$host_project_id" ]] && [[ "$project_id" != "$host_project_id" ]]; then
        is_sharedVPC='True'
    else
        is_sharedVPC='False'
    fi
    if [ -z "$kms_key" ]; then
        is_cmek_encrypted='False'
    else
        is_cmek_encrypted='True'
    fi
    echo
    echo -e "${yellow}Only Basic IAM Roles are validated using this utility. If you have custom Roles this tool might give inaccurate results."
    echo -e "${yellow}============ Composer Instance details =============="
    echo -e "Project ID: $project_id"
    echo -e "Project Number: $project_number"
    echo -e "Composer Instance: $composer_instance"
    echo -e "location: $location"
    echo -e "Shared VPC: $is_sharedVPC"
    if [ "$is_sharedVPC" == 'True' ]; then
        echo -e "Shared VPC network: $subnetwork"
    fi
    echo -e "Is Private: ${is_private:-False}"
    echo -e "CMEK Enabled: ${is_cmek_encrypted}"
    echo -e "Composer version: $version"
    echo -e "=====================================================${nc}"
    echo

    # Verifying if SA is from different project
    domain=$(echo "$service_account" | awk -F@ '{print $2}')
    service_account_project=$(echo "$domain" | awk -F. '{print $1}')
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
    if [ $default_sa == $service_account ]; then
        #echo "Need 'roles/editor' to default service account"
        check_role "$service_account" "roles/editor"
    else
        #echo "Need 'roles/composer.worker' for composer service account"
        check_role "$service_account" "roles/composer.worker"
    fi

    #Checking Composer Agent Service Account
    echo "Composer Agent Service Account: service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
    #echo "Need 'roles/composer.serviceAgent'"
    condition="roles/composer.serviceAgent"
    check_role "service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" $condition
    if [[ $version == composer-2* || $version == 2 ]]; then
        echo "Need 'roles/composer.ServiceAgentV2Ext' ( Cloud Composer v2 API Service Agent Extension) for Composer 2 instances"
        condition="roles/composer.ServiceAgentV2Ext"
        if ! check_role "service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" $condition; then
            echo "${yellow}Missing permissions at project level, checking roles/composer.ServiceAgentV2Ext role is granted at the environment service account-level ${nc}"
            check_role $service_account $condition "service-account" "service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
        fi
    fi

    #Cloud Build Service Account
    echo "Cloud build service account: $project_number@cloudbuild.gserviceaccount.com"
    #echo "Need 'roles/cloudbuild.builds.builder'"
    condition="roles/cloudbuild.builds.builder"
    check_role "$project_number@cloudbuild.gserviceaccount.com" $condition

    #Google APIs service account
    echo "Google APIs service account: $project_number@cloudservices.gserviceaccount.com"
    #echo "Need 'roles/editor'"
    condition="roles/editor"
    check_role "$project_number@cloudservices.gserviceaccount.com" $condition

    #CMEK
    if [[ "$is_cmek_encrypted" != False ]]; then
        key_name=$(echo "$kms_key" | awk -F'/' '{print $8}')
        key_ring=$(echo "$kms_key" | awk -F'/' '{print $6}')
        key_location=$(echo "$kms_key" | awk -F'/' '{print $4}')
        key_project=$(echo "$kms_key" | awk -F'/' '{print $2}')

        if [[ "${key_location}" != "${location}" ]]; then
            echo "${red}The CMEK key location is not the same as the env. location!${nc}"
            echo "See https://cloud.google.com/composer/docs/composer-2/configure-cmek-encryption#before_you_begin"
            echo "You must create a CMEK key in the same region where your environments are located. You cannot use multi-regional or global keys.${normal}"
            echo
        elif [[ "${key_project}" != "${project_id}" ]]; then
            echo -e "${yellow} Since CMEK key is hosted in a different project, please log into $key_project and run below command.${nc}"
            echo "gcloud kms keys get-iam-policy $key_name --keyring=$key_ring --location=$key_location"
        else

            condition="serviceAccount:service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"
            condition="${condition}|serviceAccount:service-$project_number@compute-system.iam.gserviceaccount.com"
            condition="${condition}|serviceAccount:service-$project_number@container-engine-robot.iam.gserviceaccount.com"
            condition="${condition}|serviceAccount:service-$project_number@gcp-sa-artifactregistry.iam.gserviceaccount.com"
            condition="${condition}|serviceAccount:service-$project_number@gcp-sa-pubsub.iam.gserviceaccount.com"
            condition="${condition}|serviceAccount:service-$project_number@gs-project-accounts.iam.gserviceaccount.com"
            echo "List of service accounts with 'roles/cloudkms.cryptoKeyEncrypterDecrypter' role are:"
            existing_roles=$(gcloud kms keys get-iam-policy "$key_name" --keyring="$key_ring" --location="$key_location" \
                --flatten="bindings[].members" \
                --format='table[box,no-heading](bindings.members)' \
                --filter="bindings.role:roles/cloudkms.cryptoKeyEncrypterDecrypter")
            highlight_roles "$condition" "${existing_roles[@]}"

        fi
    fi

    if [[ "$is_sharedVPC" == 'True' ]]; then
        echo -e "${yellow} Since this is a shared VPC network please run below command after logging into network host project: $host_project_id ${nc}"
        echo "./iamValidation.sh $subnetwork $project_number $location $is_private"
        echo
    fi

elif [[ $project_type == 2 ]]; then # Verifying Network Host Project IAM permission details.

    SUBNET=$1
    project_number=$2
    location=$3
    is_private=$4
    if [[ -z "$SUBNET" ]]; then
        read -p 'Enter subnet name: ' SUBNET
    elif [[ -z "$project_number" ]]; then
        read -p 'Enter Composer project number: ' project_number
    elif [[ -z "$location" ]]; then
        read -p 'Enter location: ' location
    elif [[ -z "$is_private" ]]; then
        read -p 'Enter True for Private(Default) and False for Public: ' is_private
        is_private=${is_private:-True}
    fi

    host_project_id=$(gcloud config list core/project --format='value(core.project)')
    host_project_number=$(gcloud projects describe $project_id --format="value(projectNumber)")

    #Checking Google APIs service account
    echo "Google APIs service account: $project_number@cloudservices.gserviceaccount.com"
    condition="roles/compute.networkUser"
    check_role "$project_number@cloudservices.gserviceaccount.com" $condition

    #Checking service project GKE service account at project level
    echo "Service project GKE service account: service-$project_number@container-engine-robot.iam.gserviceaccount.com"
    condition="roles/container.hostServiceAgentUser"
    check_role "service-$project_number@container-engine-robot.iam.gserviceaccount.com" $condition

    echo "Need 'roles/compute.networkUser' at project level / subnetwork level"
    condition="roles/compute.networkUser"
    if ! check_role "service-$project_number@container-engine-robot.iam.gserviceaccount.com" $condition; then
        condition="roles/compute.networkUser"
        echo -e "${yellow}Missing permissions at project level, checking subnetwork level$.${nc}"
        existing_roles=$(gcloud compute networks subnets get-iam-policy $SUBNET --region $location \
            --project $host_project_id --flatten='bindings[].members' --format='table[box,no-heading](bindings.role)' \
            --filter="bindings.members:service-$project_number@container-engine-robot.iam.gserviceaccount.com")
        highlight_roles "$condition" "${existing_roles[@]}"
    fi

    #Checking host project GKE service account at project level
    echo "Host project GKE service account: service-$host_project_number@container-engine-robot.iam.gserviceaccount.com"
    condition="roles/container.serviceAgent"
    check_role "service-$host_project_number@container-engine-robot.iam.gserviceaccount.com" $condition

    #Checking Composer Agent Service Account
    echo "Composer Agent Service Account at project level: service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com"

    if [[ "$is_private" == 'True' ]]; then
        echo "Need 'roles/composer.sharedVpcAgent' for Private Instance"
        condition="roles/composer.sharedVpcAgent"
    elif [[ "$is_private" == 'False' ]]; then
        echo "Need 'roles/compute.networkUser' for Public Instance"
        condition="roles/compute.networkUser"
    fi

    check_role "service-$project_number@cloudcomposer-accounts.iam.gserviceaccount.com" $condition

else
    echo "Invalid choice. Please enter 1 or 2."
    exit 1
fi
