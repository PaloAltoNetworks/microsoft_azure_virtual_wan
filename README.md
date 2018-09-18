# microsoft_azure-cortex
This project repository contains the tools to automate the creation of VPN connections between Palo Alto Networks firewall devices and the Microsoft Azure Virtual WAN Service. 

![Palo Alto Network Virtual WAN Automation Architecture] (azure-virtual-wan.png)

1. Palo Alto Networks VPN Automation Tool Overview:

1.1 Automating the creation and the configuration of all aspects of the Microsoft Virtual WAN.

    Filename: ```pan_vpn_automation.py```
    Usage: python pan_vpn_automation.py <virtual wan config json file>  

1.2 Automating the creation and configuration of all aspects of creating and establishing a VPN connection 
    on a Palo Alto Networks firewall device.

    Filename: ```panw_ipsec.py```
    Usage   : python panw_ipsec.py <ipsec configuration file> <vpn configuration file>

2. Pre-requisites for interacting with the Microsoft Virtual WAN

    2.1 A service principal with the appropriate privileges to operate on the Virtual WAN Service. 
    2.2 Microsoft Azure Tenant ID.
    2.3 Microsoft Azure Client ID.
    2.4 Microsoft Azure Client Secret. 

    2.5 Dependencies 

        2.5.1 Azure Virtual WAN resource files. These files describe the API request payload for the various 
              resources being created on Microsoft Azure 

              Sample files have been provided in the data_files directory

        2.5.2 Top level config file

              This file is the first argument provided as input to the ```pan_vpn_automation.py``` tool. 

              Sample file has been provided, called: ```az_config.json``` 


3. Pre-requisites for interacting with the Palo Alto Networks firewall device  

    3.1 IP Address of the Management Port which is reachable.
    3.2 Firewall credentials (username, password)

    3.3 Dependencies 

        3.3.1 IPSec json configuration file
              
              Sample file has been provided in file called: ```pan_ipsec_config.json ```

        3.3.2 VPN json configuration file 

              Sample file has been provided in file called: ```config1535561627450.json```
              Note: This file should be downloaded from the Microsoft Azure Virtual Wan resource page on the portal. 
