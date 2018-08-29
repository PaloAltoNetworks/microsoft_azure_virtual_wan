# This file implements the interactions with Palo Alto Networks firewalls 
# for the purpose of creation of IPSec and VPN tunnels.
# Author(s): Vinay Venkataraghavan
# Date: 8/28/2018 

#!/usr/bin/env python 

from pandevice import firewall
from pandevice import policies
from pandevice import objects
from pandevice import network

import json
import logging
import os
import sys
from pprint import pprint

logging.basicConfig(level=8)

class AzureManagedVPN:
    """
    vwan_name: Name of the VWAN as configured on Azure
    vwan_ip  : Public IP address of the VWAN endpoint
    peer_site_ip: This is the public IP address of the site that is connecting into the VWAN
    peer_site_name: The name of the remote/branch site as configured on Azure
    peer_site_address_space: The address space of the remote/branch site 
    pre_shared_key : The pre shared key to use for negotiation.
    """
    def __init__(self, vwan_ip, peer_site_ip, 
                peer_site_name, peer_site_address_space, 
                pre_shared_key):
        
        self.vwan_ip = vwan_ip
        self.peer_site_ip = peer_site_ip
        self.peer_site_name = peer_site_name
        self.peer_site_address_space = peer_site_address_space
        self.pre_shared_key = pre_shared_key 
        
    def __str__(self):
        return "Virtual WAN IP: {}\n"\
                "Peer Site IP: {}\n"\
                "Peer Site Name: {}"\
                "Peer Site Address Space: {}"\
                "Pre Shared Key: {}".format(self.vwan_ip, self.peer_site_ip,
                                            self.peer_site_name, self.peer_site_address_space, 
                                            self.pre_shared_key)

class IKEProfile:

    def __init__(self, *args, **kwargs):
        
        self.name = kwargs.get('name')
        self.authentication = kwargs.get('authentication')
        self.encryption = kwargs.get('encryption')
        self.dh_group = kwargs.get('dh_group')
        self.lifetime_secs = kwargs.get('lifetime_secs')

    def __str__(self):

        return "IKE Profile: \n"\
               "Name: {}\n"\
               "Authentication: {}\n"\
               "Encryption: {}\n"\
               "DH Group: {}\n".format(self.name, self.authentication, 
                                    self.encryption, self.dh_group)

class IPSecProfile:
    def __init__(self, *args, **kwargs):

        self.name = kwargs.get('name') 
        self.authentication = kwargs.get('authentication')
        self.encryption = kwargs.get('encryption') 
        self.dh_group = kwargs.get('dh_group') 
        self.lifetime_hrs = kwargs.get('lifetime_hrs')

    def __str__(self):
        return "IPSec Profile: \n"\
               "Name: {}\n"\
               "Authentication: {}\n"\
               "Encryption: {}\n"\
               "DH Group: {}\n"\
               "Lifetime hours: {}\n".format(self.name, self.authentication, 
                                    self.encryption, self.dh_group, self.lifetime_hrs)


class IKEGateway:
    def __init__(self, *args, **kwargs):

        self.name = kwargs.get('name')
        self.protocol_version = kwargs.get('protocol_version') 
        self.interface = kwargs.get('interface') 
        self.auth_type = kwargs.get('auth_type') 
        self.enable_passive_mode = kwargs.get('enable_passive_mode')
        self.liveness_check = kwargs.get('liveness_check')

    def __str__(self):
        return "IKE Gateway\n"\
               "Name: {}\n"\
               "Protocol Version: {}\n"\
               "Interface: {}\n"\
               "Auth Type: {}\n"\
               "Enable Passive Mode: {}\n"\
               "Liveness check: {}\n".format(self.name, self.protocol_version, 
                                        self.interface, self.auth_type, 
                                        self.enable_passive_mode, self.liveness_check) 
 
class IPSecTunnel:

    def __init__(self, *args, **kwargs):

        self.name = kwargs.get('name')
        self.key_type = kwargs.get('key_type')
        self.tunnel_interface = kwargs.get('tunnel_interface')
        self.ike_gw = args[0]
        self.ipsec_profile = args[1]

    def __str__(self):
        return "IPSec Tunnel: \n"\
               "Name: {}\n"\
               "Tunnel Interface: {}\n"\
               "Key type: {}\n"\
               "IKE Gateway: {}\n"\
               "IPSec Crypto Profile: {}".format(self.name, 
                                                 self.tunnel_interface, 
                                                 self.key_type, 
                                                 self.ike_gw,
                                                 self.ipsec_profile)

class PaloAltoVPN:

    def __init__(self, username, password, ip, ike_profile, ipsec_profile, ike_gw, ipsec_tunnel):

        self.username = username
        self.password = password
        self.ip = ip 
        self.fw_dev_hndl = firewall.Firewall(self.ip, self.username, self.password)
        
        self.ipsec_tunnel = ipsec_tunnel
        self.ike_profile = ike_profile
        self.ipsec_profile = ipsec_profile
        self.ike_gw = ike_gw

    def __str__(self):

        return "FW IP: {}\n"\
                "{} \n"\
               "{} \n"\
               "{} \n"\
               "{}\n".format(self.ip, str(self.ike_profile), 
                             str(self.ipsec_profile), 
                             str(self.ike_gw),
                             str(self.ipsec_tunnel))

    def create_ike_crypto_profile(self, name="", dh_group=[], authentication=[], 
                                   encryption=[], lifetime_secs=28800, auth_multiple=0):
        """
        Create an IKE Crypto Profile based on the submitted
        parameters.
        """
        self.ike_crypto_prof1 = network.IkeCryptoProfile(name, dh_group, authentication, encryption, lifetime_secs, None, None, None, 
        auth_multiple)
        print("%s", self.ike_crypto_prof1.element_str())
        self.fw_dev_hndl.add(self.ike_crypto_prof1) 
        self.ike_crypto_prof1.create()

    def create_ipsec_crypto_profile(self, name="", esp_encryption=[], esp_authentication=[], 
                                    ah_authentication=[], dh_group=[], lifetime_hours=1):
        """
        Create an IPSec Crypto Profile based on the submitted 
        parameters.
        """
        self.ipsec_crypto_prof1 = network.IpsecCryptoProfile(name=name, esp_encryption=esp_encryption, esp_authentication=esp_authentication, 
                                                    ah_authentication=None, 
                                                    dh_group=dh_group, lifetime_hours=lifetime_hours)
        print("%s", self.ipsec_crypto_prof1)
        self.fw_dev_hndl.add(self.ipsec_crypto_prof1)
        self.ipsec_crypto_prof1.create()


    def create_ike_gateway(self, name="", version="", enable_ipv6=False, disabled=False, peer_ip_type="ip",
                        peer_ip_value="", interface="", local_ip_address_type="ip", local_ip_address="",
                        auth_type='pre-shared-key', pre_shared_key="",
                        enable_passive_mode=True, enable_nat_traversal=False,
                        ikev2_crypto_profile="", ikev2_cookie_validation=False,
                        ikev2_send_peer_id=False, 
                        enable_liveness_check=True, liveness_check_interval=5):
        """
        Create an IKE Gateway element on the Palo Alto Firewall
        """
        
        ike_gw = network.IkeGateway(name=name, version='ikev2', enable_ipv6=False,
                                disabled=False, peer_ip_type='ip', peer_ip_value=peer_ip_value, 
                                interface='ethernet1/1', 
                                #local_ip_address_type='ip', local_ip_address='127.0.0.1', 
                                auth_type='pre-shared-key', pre_shared_key=pre_shared_key,
                                local_id_type=None, local_id_value=None, 
                                peer_id_type=None, peer_id_value=None, peer_id_check=None,
                                local_cert=None, cert_enable_hash_and_url=False, cert_base_url=None, 
                                cert_use_management_as_source=False, cert_permit_payload_mismatch=False, 
                                cert_profile=None, cert_enable_strict_validation=False, 
                                enable_passive_mode=True, 
                                #enable_nat_traversal=False, 
                                #nat_traversal_keep_alive=28800, nat_traversal_enable_udp_checksum=False,
                                enable_fragmentation=False, 
                                # ikev1
                                ikev1_exchange_mode=None, ikev1_crypto_profile=None,
                                enable_dead_peer_detection=False, dead_peer_detection_interval=99,
                                dead_peer_detection_retry=10,
                                ikev2_crypto_profile=ikev2_crypto_profile, ikev2_cookie_validation=ikev2_cookie_validation,
                                ikev2_send_peer_id=ikev2_send_peer_id, enable_liveness_check=enable_liveness_check, 
                                liveness_check_interval=liveness_check_interval)
        print("IKE GW Configuration: %s", ike_gw.element_str())
        self.fw_dev_hndl.add(ike_gw)
        ike_gw.create()

    def create_ipsec_tunnel(self, name, tunnel_interface, key_type, ike_gw_name, 
                        ipsec_crypto_profile, ipv6=False, enable_tunnel_montior_mode=False,
                        disable_tunnel=False):
        """
        Create an IPSec Tunnel between the two endpoints
        """

        self.ipsec_tunnel = network.IpsecTunnel(name=name, tunnel_interface=tunnel_interface, type=key_type,
                                       ak_ike_gateway=ike_gw_name, ak_ipsec_crypto_profile=ipsec_crypto_profile,
                                       ipv6=ipv6, enable_tunnel_monitor=enable_tunnel_montior_mode, 
                                       disabled=disable_tunnel)
        self.fw_dev_hndl.add(self.ipsec_tunnel)
        self.ipsec_tunnel.create()

def parse_config_files(filename):
    """
    Parse the config file and return json data
    """
    data = {}
    with open(filename) as f:
        data = json.load(f)
    
    return data 

def extract_azure_vpn_config(data, registered_sitename):
    """
    Extract relevant data from the Azure Configurations
    """
    for site_config in data:
        
        site_name = site_config['vpnSiteConfiguration']['Name']
        if site_name == registered_sitename:
            peer_ip = site_config['vpnSiteConfiguration']['IPAddress']
            vpnSiteConnection = site_config['vpnSiteConnections'][0]
            peer_subnet = None
            if 'ConnectedSubnets' in vpnSiteConnection['hubConfiguration']:
                peer_subnet = vpnSiteConnection['hubConfiguration']['ConnectedSubnets'][0]
            vwan_ip = vpnSiteConnection['gatewayConfiguration']['IpAddresses']
            psk = vpnSiteConnection['connectionConfiguration']['PSK']
            print psk
            az_vwan = AzureManagedVPN(vwan_ip['Instance0'], peer_ip, site_name, 
                                    peer_subnet, psk)
            print str(az_vwan)
            return az_vwan

def parse_fw_configs(filename):
    """
    Parse the firewall config file and extract data.
    """
    fw_data = parse_config_files(filename)

    ike_prof_data = fw_data.get('ike_profile') 
    _ike_prof = IKEProfile(**ike_prof_data)

    
    ipsec_prof_data = fw_data.get('ipsec_profile')
    _ipsec_prof = IPSecProfile(**ipsec_prof_data)
    
    ike_gw_data = fw_data.get('ike_gw')
    _ike_gw = IKEGateway(**ike_gw_data)

    ipsec_tunnel_data = fw_data.get('ipsec_tunnel')
    _ipsec_tunnel = IPSecTunnel(_ike_gw.name, _ipsec_prof.name, **ipsec_tunnel_data)
    fw_creds = fw_data.get('creds')

    print("\nCreate a connection with the firewall at: {}\n".format(fw_creds.get('fw_ip')))
    fw_ip = fw_creds.get('fw_ip')
    username = fw_creds.get('username')
    password = fw_creds.get('password')

    pan_vpn_hndl = PaloAltoVPN(username, password, fw_ip, _ike_prof, _ipsec_prof, _ike_gw, _ipsec_tunnel)
    return pan_vpn_hndl

def main():

    if len(sys.argv) != 4:
        print("Usage: %s <palo alto config filename> <azure vpn configuration filename> <registered branch name in azure>",
                sys.argv[0])
        sys.exit(1)
     
    pan_vpn_hndl = parse_fw_configs(sys.argv[1])
    print str(pan_vpn_hndl)
    
    az_data = parse_config_files(sys.argv[2])
    az_vpn_hndl = extract_azure_vpn_config(az_data, sys.argv[3])
    
    pan_vpn_hndl.fw_dev_hndl.refresh_system_info()
    pan_vpn_hndl.create_ike_crypto_profile(pan_vpn_hndl.ike_profile.name,
                                           pan_vpn_hndl.ike_profile.dh_group, 
                                           pan_vpn_hndl.ike_profile.authentication, 
                                           pan_vpn_hndl.ike_profile.encryption)

    pan_vpn_hndl.create_ipsec_crypto_profile(pan_vpn_hndl.ipsec_profile.name, 
                                            pan_vpn_hndl.ipsec_profile.encryption, 
                                            pan_vpn_hndl.ipsec_profile.authentication, 
                                            None, pan_vpn_hndl.ipsec_profile.dh_group, 
                                            pan_vpn_hndl.ipsec_profile.lifetime_hrs)

    pan_vpn_hndl.create_ike_gateway(pan_vpn_hndl.ike_gw.name, pan_vpn_hndl.ike_gw.protocol_version, 
                                    False, False, 'ip',
                                    az_vpn_hndl.vwan_ip, pan_vpn_hndl.ike_gw.interface, 
                                    'ip', None, 
                                    pan_vpn_hndl.ike_gw.auth_type, 
                                    az_vpn_hndl.pre_shared_key, 
                                    True, False, 
                                    pan_vpn_hndl.ike_profile.name, 
                                    False, False, True, 5)

    pan_vpn_hndl.create_ipsec_tunnel(pan_vpn_hndl.ipsec_tunnel.name, 
                                    pan_vpn_hndl.ipsec_tunnel.tunnel_interface, 
                                    pan_vpn_hndl.ipsec_tunnel.key_type, 
                                    pan_vpn_hndl.ipsec_tunnel.ike_gw, 
                                    pan_vpn_hndl.ipsec_tunnel.ipsec_profile)

    pan_vpn_hndl.fw_dev_hndl.commit(sync=True)

    print("\n\n***********************************")
    print("\nConfiguration successfully applied.")
    print("\n\n***********************************")
if __name__ == "__main__":
    main()