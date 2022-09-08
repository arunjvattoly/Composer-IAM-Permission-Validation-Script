# Composer Troubleshooting Script (No Environment Needed):

### Supports
* IAM permission validation for Composer 1, 2 instances without the need of an existing environment.

### Prerequisites:
* Cloud SDK

### How to use: 
* Download the latest script (iamValidationNoEnvironment.sh)
* Make the script executable by running,
  ```
  chmod +x composerValidation.sh
  ```
* Log into the GCP project having failed composer instance,
  ```
  gcloud init
  ```
* Execute the bash script by running
  ```
  ./composerValidation.sh
  ```
Follow instruction and enter the details as prompted.

Note: When running in the service project this script will not provide network details, as it is not possible to run the command `gcloud composer environments describe <composer-env> –-location <location> --format="table(config.privateEnvironmentConfig)"` in case the environment is private
