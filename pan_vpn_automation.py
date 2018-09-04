#!/usr/bin/env python

import os, sys, subprocess
import json, uuid, time

class CommandProcessor:

    def __init__(self):
         pass

    def run_command(self, cmd):

        cmd_stat = None
        try:
            cmd_stat = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
            output, err = cmd_stat.communicate()

            status = cmd_stat.wait()
            print "Command output: ", output
            print "Command exit status / return code: ", status
        except Exception, e:
            print("Return code: {}\n"\
                "Exception: {}".format(cmd_stat.returncode, e)
            )

    def run_check_output(self, cmd):
        
        output = subprocess.check_output(cmd, shell=True)
        print output
        
        if "Updating" in output:
            return 1
        else:
            return 0 

    def retry_run_check_output(self, cmd):
        
        cntr = 0
        print "Retrying command..."
        while True and cntr < 600:
            output = subprocess.check_output(cmd, shell=True)
            print output
            if "Updating" in output:
                time.sleep(10) 
                continue
            elif "Succeeded" in output:
                "Command successfully completed"
                return 

    def construct_command(self, command, azure_hndle, resource_name, request_json_filename):
        """
        Construct the command to be executed. 
        """
        
        final_cmd = "{} -op:{} -subscriptionid:{} -apiversion:{} -endpoint:{} -resourcegroup:{} -resourcename:{} -requestjsonfile:{}"\
                    .format(azure_hndle.azure_driver_filename, command, azure_hndle.subscription, azure_hndle.apiversion,
                            azure_hndle.endpoint, azure_hndle.resource_group, resource_name, request_json_filename)
        return final_cmd 


class Azure:

    commands_list = {
        "PutVirtualWan": "",
        "PutVpnSite": "",
        "PutVirtualHub": "",
        "PutVpnGateway": "",
        "GetVpnConfiguration": ""
    }

    command_order = ['PutVirtualWan', 'PutVpnSite', 'PutVirtualHub','PutVpnGateway']
    get_commands = {
        "PutVirtualHub": "GetVirtualHub",
        "PutVpnGateway": "GetVpnGateway",
        "PutVirtualWan": "GetVirtualWan",
        "PutVpnSite": "GetVpnSite"
    }

    def __init__(self, azure_driver_filename, resource_group, resource_prefix, subscription, apiversion, endpoint, **kwargs):
        self.azure_driver_filename = azure_driver_filename
        self.subscription = subscription
        self.apiversion = apiversion
        self.endpoint = endpoint
        self.resource_group = resource_group
        self.cmd_to_file_map = self._construct_cmd_to_config_map(**kwargs.get('config_filemap'))
        self.resource_prefix = resource_prefix
        self.resource_names = kwargs['resource_names']

    def __str__(self):
        return "Azure Details: \n"\
               "Subscription: {}\n"\
               "API Version: {}\n"\
               "Endpoint: {}\n"\
               "Resource Names: {}\n"\
               "Command to File Map: {}\n".format(self.subscription, 
                                       self.apiversion, 
                                       self.endpoint,
                                       self.resource_names,
                                       self.commands_list)

    def _construct_cmd_to_config_map(self, **kwargs):

        for key, value in kwargs.items():
            if "wan" in key:
                self.commands_list['PutVirtualWan'] = value
            elif "site" in key: 
                self.commands_list['PutVpnSite'] = value
            elif "hub" in key: 
                self.commands_list["PutVirtualHub"] = value
            elif "gateway" in key:
                self.commands_list['PutVpnGateway'] = value

    def get_resource_name_for_command(self, command):
        """
        Retrieve the name of the resource to use for the command.
        """
        if "VirtualWan" in command:
            return self.resource_names['VirtualWanName']
        elif "VpnSite" in command:
            return self.resource_names['VpnSiteName']
        elif "VirtualHub" in command:
            return self.resource_names['VirtualHubName']
        elif "VpnGateway" in command:
            return self.resource_names['VpnGatewayName']

    def parse_output(self, output):
        #print output
        print type(output)
        
        sl = output.splitlines()
        for _line in sl:
            if 'provisioningState' in _line:
                _v = _line.split(":")
                print _v[1], type(_v[1])


def parse_azure_config_file(filename):
    """
    Parse and configure the Azure Interface
    """
    data = None
    with open(filename, 'r') as fd:
        data = json.load(fd)
    resource_files = data.get('azure_resources', None)
    if not resource_files:
        raise Exception('The Azure resource files have not been populated."\
                         Please check the json configuration file and populate these sections.')
        
    az_hndl = Azure(data.get('azure_driver_filename'),
                    data.get('resource_group'),
                    data.get('resource_prefix'),
                    data.get('subscription'),
                    data.get('apiversion'),
                    data.get('endpoint'),
                    **resource_files
                    )
    print str(az_hndl)
    return az_hndl

def main():
    print "Palo Alto Networks VPN Automation System"

    az_hndl = parse_azure_config_file(sys.argv[1])
    cmdp = CommandProcessor()
    
    for _cmd in az_hndl.command_order: 
        print _cmd
        cur_cmd = None
        resource_name = az_hndl.get_resource_name_for_command(_cmd)
        print resource_name
        cur_cmd = cmdp.construct_command(_cmd, az_hndl, resource_name, az_hndl.commands_list.get(_cmd))
        
        time.sleep(5)
        print "Executing command: ", cur_cmd

        output = cmdp.run_check_output(cur_cmd)
        if output:
            _new_op = az_hndl.get_commands.get(_cmd)
            print _new_op
            _new_cmd = cmdp.construct_command(_new_op, az_hndl, resource_name, az_hndl.commands_list.get(_cmd))
            cmdp.retry_run_check_output(_new_cmd)

if __name__ == "__main__":
    main()
