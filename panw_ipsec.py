# This file implements the interactions with Palo Alto Networks firewalls 
# for the purpose of creation of IPSec and VPN tunnels.

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
        

class PaloAltoVPN:

    def __init__(self, username, password, ip):
        self.username = username
        self.password = password
        self.ip = ip 
        self.fw_dev_hndl = firewall.Firewall(self.ip, self.username, self.password)
        self.ike_crypto_prof1 = None
        self.ipsec_crypto_prof1 = None
        self.ike_gw = None
        self.ipsec_tunnel = None

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

        self.ike_gw = network.IkeGateway(name=name, version='ikev2', enable_ipv6=False,
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
        print("IKE GW Configuration: %s", self.ike_gw.element_str())
        self.fw_dev_hndl.add(self.ike_gw)
        self.ike_gw.create()

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
    pprint(data)
    return data 

def extract_azure_vpn_config(data, registered_sitename):
    """
    Extract relevant data from the Azure Configurations
    """
    for site_config in data:
        print("%s", site_config)
        site_name = site_config['vpnSiteConfiguration']['Name']
        if site_name == registered_sitename:
            peer_ip = site_config['vpnSiteConfiguration']['IPAddress']
            vpnSiteConnection = site_config['vpnSiteConnections'][0]
            peer_subnet = vpnSiteConnection['hubConfiguration']['ConnectedSubnets'][0]
            print('Peer subnet address space: {}'.format(peer_subnet))
            print("Peer ip: {}".format(peer_ip))
            vwan_ip = vpnSiteConnection['gatewayConfiguration']['IpAddresses']
            psk = vpnSiteConnection['connectionConfiguration']['PSK']
            print("vwan ip: {} PSK: {}".format(vwan_ip, psk))
            az_vwan = AzureManagedVPN(vwan_ip['Instance0'], peer_ip, site_name, 
                                    peer_subnet, psk)
            pprint(az_vwan)
            return az_vwan

def main():

    if len(sys.argv) != 4:
        print("Usage: %s <palo alto config filename> <azure vpn configuration filename> <registered branch name in azure>",
                sys.argv[0])
        sys.exit(1)
    

    data = {}
    az_data = {}
     
    fw_data = parse_config_files(sys.argv[1])
    az_data = parse_config_files(sys.argv[2])
    az_vpn_hndl = extract_azure_vpn_config(az_data, sys.argv[3])
    
    print("Establish a connection with the firewall at: {}".format(data.get('fw_ip')))
    fw_ip = fw_data.get('fw_ip')
    username = fw_data.get('username')
    password = fw_data.get('password')

    print("Shared key is: {}".format(az_vpn_hndl.pre_shared_key))
    
    pan_vpn_hndl = PaloAltoVPN(username, password, fw_ip)
    
    pan_vpn_hndl.fw_dev_hndl.refresh_system_info()
    pan_vpn_hndl.create_ike_crypto_profile("cortex_ike_crypto1",
                              ["group2"], ["sha1"], ["aes-256-cbc", "3des"])
    pan_vpn_hndl.create_ipsec_crypto_profile('cortex_ipsec_crypto1', ['aes-128-cbc', '3des'], ['sha1'], None, 'no-pfs', 1)

    pan_vpn_hndl.create_ike_gateway("ike_gw2", 'ikev2', False, False, 'ip',
                       az_vpn_hndl.vwan_ip, 'ethernet1/1', 'ip', None, 
                       'pre-shared-key', az_vpn_hndl.pre_shared_key, True, False, 
                        'cortex_ike_crypto1', False, False, True, 5)

    pan_vpn_hndl.create_ipsec_tunnel('ipsec_tunnel2', 'tunnel.2', 'auto-key', 'ike_gw2', 
                        'cortex_ipsec_crypto1')

if __name__ == "__main__":
    main()