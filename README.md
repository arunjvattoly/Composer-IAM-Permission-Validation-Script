# Composer Troubleshooting scripts:
* IAM permission validation for Composer 1/2 instances.

Pre-requisites:
* Failed composer instance 
* Cloud SDK

How to use: 

* Download the latest script(iamValidation.sh)
* Make the script executable by running,
  ```
  chmod +x iamValidation.sh
  ```
* Log into the GCP project having failed composer instance,
  ```
  gcloud auth login
  ```
* Execute the bash script by running
  ```
  ./iamValidation.sh
  ```
Follow instruction and enter the details as prompted.

