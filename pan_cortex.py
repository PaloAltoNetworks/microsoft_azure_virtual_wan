#!/usr/bin/env python
import adal 
import json 
import os.path 
import requests 
import sys 

# Globals 
file_name = 'pan_cortex.py' 
aad_constants_file_name = 'aadtokenconstants.json' 
args_dict = {} 
op_functions_dict = {} 

# Resource types 
resource_type_virtual_hubs = 'virtualHubs' 
resource_type_virtual_wans = 'virtualWans' 
resource_type_vpn_sites = 'vpnSites' 
resource_type_vpn_gateways = 'vpngateways'

# Segments 
segment_vpn_configuration = '/vpnConfiguration'

# HTTP methods 
http_method_delete = 'delete' 
http_method_get = 'get' 
http_method_post = 'post' 
http_method_put = 'put' 

# Operation names 
op_delete = 'delete' 
op_deletevirtualwan = 'deletevirtualwan' 
op_deletevpnsite = 'deletevpnsite'

op_get = 'get' 
op_getvirtualwan = 'getvirtualwan' 
op_getvpnconfiguration = 'getvpnconfiguration' 
op_getvpnsite = 'getvpnsite' 
op_post = 'post' 
op_put = 'put' 
op_putvirtualwan = 'putvirtualwan' 
op_putvpnsite = 'putvpnsite' 

# new operations 
op_putvirtualhub = 'putvirtualhub'
op_getvirtualhub = 'getvirtualhub'
op_putvpngateway = 'putvpngateway'
op_getvpngateway = 'getvpngateway'
op_deletevirtualhub = 'deletevirtualhub'
op_deletevpngateway = 'deletevpngateway'
# Arguments 
arg_op = 'op' 
arg_subscriptionid = 'subscriptionid' 
arg_resourcegroup = 'resourcegroup' 
arg_resourcename = 'resourcename' 
arg_apiversion = 'apiversion' 
arg_endpoint = 'endpoint' 
arg_requestheaders = 'requestheaders' 
arg_requestjsonfile = 'requestjsonfile' 
arg_requesturl = 'requesturl' 


# Keys 
key_tenantid = 'tenantid' 
key_clientid = 'clientid' 
key_clientsecret = 'clientsecret' 
key_function = 'function' 
key_httpMethod = 'httpMethod' 
key_resourceType = 'resourceType' 

def get_file(pathToFile): 
    from pathlib import Path 
    input_json_file_path = pathToFile 
    input_json_file = Path(input_json_file_path) 
    if not input_json_file.is_file(): 
        print('File {} not found. Quitting.'.format(input_json_file_path)) 
        exit() 
    input_json_file = open(input_json_file_path, 'r') 
    return input_json_file 

def validate_strings_to_be_non_empty(names=[], values=[]): 
    if len(names) < 1: 
        return False 
    if len(values) < len(names): 
        return False 

    for i in range(len(names)): 
        name = names[i] 
        value = values[i] 
        if not value or value.isspace(): 
            print(name + ' cannot be empty.') 
            return False 
    return True

def validate_arguments(argumentNames=[]): 
    if len(argumentNames) < 1: 
        return False 
    for name in argumentNames: 
        if not name in args_dict: 
            return False 

        if not args_dict[name] or args_dict[name].isspace(): 
            print(name + ' cannot be empty.') 
            return False 
    return True 

def pretty_print_json_string(json_string): 
    if not json_string or json_string.isspace(): 
        return 
    parsed_json = json.loads(json_string) 
    print(json.dumps(parsed_json, indent=4, sort_keys=True)) 
    return 

def pretty_print_json(json_object): 
    if not json_object: 
        return 
    print(json.dumps(json_object, indent=4, sort_keys=True)) 
    return 

def print_response(response_object): 
    if response_object == None: 
        print("Nothing to display!") 
        return 
    # Get the status 
    response_message = 'Success!' 
    if not response_object.ok: 
        response_message = 'Failure!' 
    # Try to print the JSON 
    print("{}\n".format(response_message)) 
    try: 
        pretty_print_json(response_object.json()) 
    except: 
        try: 
            print("Status code: {}.".format(response_object.status_code)) 
        except: pass 
    return 

def get_access_token(): 
    authentication_endpoint = 'https://login.microsoftonline.com/' 
    resource = 'https://management.core.windows.net/'
    # Read from the file 
    aad_constants_file = get_file(aad_constants_file_name) 
    aad_constants = json.loads(aad_constants_file.read()) 
    
    # Set the values 
    tenant_id = aad_constants[key_tenantid] 
    client_id = aad_constants[key_clientid] 
    client_secret = aad_constants[key_clientsecret] 
    
    # get an Azure access token using the adal library 
    context = adal.AuthenticationContext(authentication_endpoint + tenant_id) 
    token_response = context.acquire_token_with_client_credentials( resource, client_id, client_secret) 
    access_token = token_response.get('accessToken') 
    return access_token 


def get_command_line_arguments(arguments): 
    if len(arguments) < 2: 
        return {} 
    # Process the arguments 
    for arg in arguments[1:]: 
        # Check if this is an argument 
        if not arg.startswith('-'): 
            continue 
        # Get the index of : and get the key/value pair 
        arg = arg[1:] 
        seperator_index = -1 
        try: 
            seperator_index = arg.index(':') 
        except: pass 
        
        key = '' 
        value = '' 
        if seperator_index >=1: 
            key = arg[:seperator_index].lower() 
            if seperator_index < len(arg) - 1: 
                value = arg[seperator_index + 1:] 
        else: 
            # This operator is a switch 
            key = arg[0:].lower() 

        # Add the key/value pair 
        if key == arg_op: 
            value = value.lower() 
        if not key.isspace() and not key is '' and not key is ':': 
            args_dict[key] = value 
    
    return

def get_request_headers(requestHeaders = None): 
    headers = requestHeaders 
    if requestHeaders == None: 
        # Set the header values 
        headers = {} 
        headers["Content-Type"] = "application/json" 
    # Get and set the token 
    access_token = get_access_token() 
    headers["Authorization"] = 'Bearer {}'.format(access_token) 
    return headers 

# ================================================================================ # REST METHODS # ================================================================================ 

def perform_delete_operation(endpoint): 
    # Make the REST call 
    access_token = get_access_token() 
    headers = {"Authorization": 'Bearer ' + access_token} 
    return requests.delete(endpoint, headers=headers) 
    
def perform_get_operation(endpoint): 
    # Make the REST call 
    access_token = get_access_token() 
    headers = {"Authorization": 'Bearer ' + access_token} 
    return requests.get(endpoint, headers=headers) 

def perform_post_operation(endpoint, requestJson, requestHeaders = None): 
    # Make the REST call 
    headers = get_request_headers(requestHeaders) 
    return requests.post(endpoint, headers=headers, json=requestJson) 

def perform_put_operation(endpoint, requestJson, requestHeaders = None): 
    # Make the REST call 
    headers = get_request_headers(requestHeaders) 
    return requests.put(endpoint, headers=headers, json=requestJson) 

# ================================================================================ 
# ================================================================================ 
# OPERATION METHODS 
# # ================================================================================ 


def get_or_delete(httpmethod, opName, skipvalidation = False): 
    # Validate arguments 
    if not skipvalidation: 
        if not validate_arguments([arg_requesturl]): 
            print('Some of the arguments are missing, or are null.\n') 
            print(
                'Usage: {} -op:{} -{}:<{} url>', 
                file_name, 
                opName, 
                arg_requesturl, 
                httpmethod.upper()
            )
            exit()
    
    # GET/DELETE the resource 
    response_object = {} 
    http_method = httpmethod.lower() 
    endpoint = args_dict[arg_requesturl] 
    if http_method == http_method_get: 
        response_object = perform_get_operation(endpoint) 
    if http_method == http_method_delete: 
        response_object = perform_delete_operation(endpoint) 
    
    print_response(response_object) 
    return

def get_or_delete_resource(httpmethod, opName, resourceType): 
    # Validate arguments 
    http_method = httpmethod.lower() 
    if http_method == http_method_get: 
        if not validate_arguments([arg_subscriptionid, arg_apiversion, arg_endpoint]): 
            print('Some of the arguments are missing, or are null.\n') 
            print( 'Usage: {} -op:{} -{}:<subscription id> [-{}:<resource group>] [-{}:<resource name>] -{}:<api version> -{}:<ARM endpoint>', 
                    file_name, opName, arg_subscriptionid, arg_resourcegroup, arg_resourcename, arg_apiversion, arg_endpoint ) 
            exit() 
    else: 
        if not validate_arguments([arg_subscriptionid, arg_resourcegroup, arg_resourcename, arg_apiversion, arg_endpoint]): 
            print('Some of the arguments are missing, or are null.\n') 
            print( 'Usage: {} -op:{} -{}:<subscription id> -{}:<resource group> -{}:<resource name> -{}:<api version> -{}:<ARM endpoint>', 
            file_name, opName, arg_subscriptionid, arg_resourcegroup, arg_resourcename, arg_apiversion, arg_endpoint ) 
            exit() 
    
    # Initialize the endpoint 
    # # The default endpoint to get/delete a resource 
    endpoint = ''

    # The endpoint changes for GET for subscriptions and resource groups 
    if http_method == http_method_get: 
        resource_group = '' 
        if arg_resourcegroup in args_dict: 
            if args_dict[arg_resourcegroup]: 
                resource_group = args_dict[arg_resourcegroup] 
        
        resource_name = '' 
        if arg_resourcename in args_dict: 
            if args_dict[arg_resourcename]: 
                resource_name = args_dict[arg_resourcename] 

        # Get the resource 
        if (resource_group and not resource_group.isspace()) and (resource_name and not resource_name.isspace()): 
            print('\nGetting {} resource {}...\n\n'.format(resourceType.upper(), resource_name)) 
            endpoint = '{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/{}/{}?api-version={}'.format( 
                args_dict[arg_endpoint], args_dict[arg_subscriptionid], resource_group, resourceType, resource_name, args_dict[arg_apiversion] )

        # Get all resources in resource group 
        if (resource_group and not resource_group.isspace()) and (not resource_name or resource_name.isspace()): 
            print('\nGetting all {} resources in resource group {}...\n\n'.format(resourceType.upper(), resource_group)) 
            endpoint = '{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/{}?api-version={}'.format( 
                args_dict[arg_endpoint], args_dict[arg_subscriptionid], args_dict[arg_resourcegroup], resourceType, args_dict[arg_apiversion] ) 
        
        # Get all resources in subscription 
        if (not resource_group or resource_group.isspace()) and (not resource_name or resource_name.isspace()): 
            print('\nGetting all {} resources in subscription {}...\n\n'.format(resourceType.upper(), args_dict[arg_subscriptionid])) 
            endpoint = '{}/subscriptions/{}/providers/Microsoft.Network/{}?api-version={}'.format( 
                args_dict[arg_endpoint], args_dict[arg_subscriptionid], resourceType, args_dict[arg_apiversion] )
        
    else: 
        endpoint = '{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/{}/{}?api-version={}'.format( 
            args_dict[arg_endpoint], args_dict[arg_subscriptionid], args_dict[arg_resourcegroup], resourceType, args_dict[arg_resourcename], 
            args_dict[arg_apiversion] ) 
    
    # GET/DELETE the resource 
    args_dict[arg_requesturl] = endpoint 
    get_or_delete(httpmethod, opName, True) 
    return 

def put_or_post(httpmethod, opName, skipvalidation = False): 
    
    # Validate arguments 
    if not skipvalidation: 
        if not validate_arguments([arg_requesturl, arg_requestjsonfile]): 
            print('Some of the arguments are missing, or are null.\n') 
            print( 'Usage: {} -op:{} -{}:<{} url> -{}:<path to request json file> [-{}:<request headers as a JSON string>]', 
            file_name, opName, arg_requesturl, httpmethod.upper(), arg_requestjsonfile, arg_requestheaders ) 
            exit() 
    
    # Build input JSON 
    input_json_file = get_file(args_dict[arg_requestjsonfile]) 
    request_json = json.loads(input_json_file.read()) 
    print("\nIssuing a {} command for the following resource:\n".format(httpmethod.upper())) 
    pretty_print_json(request_json) 
    
    # PUT/POST the resource 
    endpoint = args_dict[arg_requesturl] 
    response_object = {} 
    
    request_headers = None 
    if arg_requestheaders in args_dict: 
        request_headers = json.loads(args_dict[arg_requestheaders]) 
    
    http_method = httpmethod.lower() 
    if http_method == http_method_put:
        response_object = perform_put_operation(endpoint, request_json, request_headers)

    if http_method == http_method_post: 
        response_object = perform_post_operation(endpoint, request_json, request_headers) 
    
    print_response(response_object) 
    print("\n") 
    return 

def put_or_post_resource(httpmethod, opName, resourceType): 
    # Validate arguments 
    if not validate_arguments([arg_subscriptionid, arg_resourcegroup, arg_resourcename, 
                                arg_apiversion, arg_endpoint, arg_requestjsonfile]): 
        print('Some of the arguments are missing, or are null.\n') 
        print( 'Usage: {} -op:{} -{}:<subscription id> -{}:<resource group> -{}:<resource name> -{}:<api version> -{}:<ARM endpoint> -{}:<path to request json file>', 
                file_name, opName, arg_subscriptionid, arg_resourcegroup, arg_resourcename, arg_apiversion, arg_endpoint, 
                arg_requestjsonfile ) 
        exit() 
    
    # Initialize the endpoint 
    vpn_configuration_segment = '' 
    if opName.lower() == op_getvpnconfiguration: 
        vpn_configuration_segment = segment_vpn_configuration 
        
    # Set the endpoint 
    args_dict[arg_requesturl] = '{}/subscriptions/{}/resourceGroups/{}/providers/Microsoft.Network/{}/{}{}?api-version={}'.format( 
                                    args_dict[arg_endpoint], args_dict[arg_subscriptionid], args_dict[arg_resourcegroup], resourceType, 
                                    args_dict[arg_resourcename], vpn_configuration_segment, args_dict[arg_apiversion] ) 
    print("Issuing a {} command for the following resource:\n\n".format(httpmethod.upper())) 
    put_or_post(httpmethod, opName, True) 
    return

# ================================================================================ 
# ================================================================================ 
# MAIN METHODS

# ================================================================================ 
def main(args): 
    # Get the arguments 
    get_command_line_arguments(args) 
    
    # Verify 
    if not arg_op in args_dict: 
        print('Operation not specified.') 
        exit() 
    
    # Initialize operations dictionary 
    
    op_functions_dict[op_deletevirtualwan] = {key_httpMethod: http_method_delete, key_function: get_or_delete_resource, key_resourceType: resource_type_virtual_wans} 
    op_functions_dict[op_deletevpnsite] = {key_httpMethod: http_method_delete, key_function: get_or_delete_resource, key_resourceType: resource_type_vpn_sites} 
    op_functions_dict[op_getvirtualwan] = {key_httpMethod: http_method_get, key_function: get_or_delete_resource, key_resourceType: resource_type_virtual_wans} 
    op_functions_dict[op_getvpnconfiguration] = {key_httpMethod: http_method_post, key_function: put_or_post_resource, key_resourceType: resource_type_virtual_wans} 
    op_functions_dict[op_getvpnsite] = {key_httpMethod: http_method_get, key_function: get_or_delete_resource, key_resourceType: resource_type_vpn_sites} 
    op_functions_dict[op_putvirtualwan] = {key_httpMethod: http_method_put, key_function: put_or_post_resource, key_resourceType: resource_type_virtual_wans} 
    op_functions_dict[op_putvpnsite] = {key_httpMethod: http_method_put, key_function: put_or_post_resource, key_resourceType: resource_type_vpn_sites} 

    # new operations
    op_functions_dict[op_putvirtualhub] = {key_httpMethod: http_method_put, key_function: put_or_post_resource, key_resourceType: resource_type_virtual_hubs}
    op_functions_dict[op_getvirtualhub] = {key_httpMethod: http_method_get, key_function: get_or_delete_resource, key_resourceType: resource_type_virtual_hubs}
    op_functions_dict[op_putvpngateway] = {key_httpMethod: http_method_put, key_function: put_or_post_resource, key_resourceType: resource_type_vpn_gateways}
    op_functions_dict[op_getvpngateway] = {key_httpMethod: http_method_get, key_function: get_or_delete_resource, key_resourceType: resource_type_vpn_gateways}
    op_functions_dict[op_deletevirtualhub] = {key_httpMethod: http_method_delete, key_function: get_or_delete_resource, key_resourceType: resource_type_virtual_hubs}
    op_functions_dict[op_deletevpngateway] = {key_httpMethod: http_method_delete, key_function: get_or_delete_resource, key_resourceType: resource_type_vpn_gateways}
    # Vanilla operations 
    op_functions_dict[op_delete] = {key_httpMethod: http_method_delete, key_function: get_or_delete} 
    op_functions_dict[op_get] = {key_httpMethod: http_method_get, key_function: get_or_delete} 
    op_functions_dict[op_post] = {key_httpMethod: http_method_post, key_function: put_or_post} 
    op_functions_dict[op_put] = {key_httpMethod: http_method_put, key_function: put_or_post} 
    
    # Call the operation 
    op_name = args_dict[arg_op] 
    if op_name in op_functions_dict: 
        op_info = op_functions_dict[op_name] 
        if not op_info[key_resourceType]: 
            op_info[key_function](op_info[key_httpMethod], op_name) 
        else: 
            op_info[key_function](op_info[key_httpMethod], op_name, op_info[key_resourceType]) 
    else: 
        print('Invalid operation name specified.') 
    return 

# Call main function 
main(sys.argv)