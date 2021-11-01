# Splunk Patch and Reboot Fabric Script
Fabric script to help manage OS patching for Splunk enterprise clusters.

## What this will do
- Checks the status of the splunk cluster prior to updating any node and proceed only if all nodes are healthy.
- Iterate through a list of splunk nodes, performing the steps needed to apply OS updates and then reboot.
  - In the event no updates are required, the script continues without making any changes.

## Getting started
- Verify you have a splunk rest user setup and make sure it can access the API on the CM
- Copy **inventory.yml.example** to **inventory.yml** 
- Update **inventory.yml** with the list of splunk nodes
- Update the value for **splunk_cm_api_url** to match the address of your CM
- Make sure you can ssh to the splunk nodes you want to run this against
  - It's recommended to use ssh key based authentication
- Install requirements using the requirements.txt file:
    ```bash
    python3 -m pip install -r requirements.txt
    ```
