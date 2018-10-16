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
        
        self.vwan_ip0 = vwan_ip.get("Instance0", None)
        self.vwan_ip1 = vwan_ip.get("Instance1", None)
        self.peer_site_ip = peer_site_ip
        self.peer_site_name = peer_site_name
        self.peer_site_address_space = peer_site_address_space
        self.pre_shared_key = pre_shared_key 
        
    def __str__(self):
        return "Virtual WAN IP0: {}\n"\
                "Virtual WAN IP1: {}\n"\
                "Peer Site IP: {}\n"\
                "Peer Site Name: {}"\
                "Peer Site Address Space: {}"\
                "Pre Shared Key: {}".format(self.vwan_ip0, self.vwan_ip1, 
                                            self.peer_site_ip,
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
        self.lifetime_hrs = kwargs.get('lifetime_hrs', None)
        self.lifetime_secs = kwargs.get('lifetime_secs', None)

    def __str__(self):
        return "IPSec Profile: \n"\
               "Name: {}\n"\
               "Authentication: {}\n"\
               "Encryption: {}\n"\
               "DH Group: {}\n"\
               "Lifetime hours: {}\n"\
               "Lifetime seconds: {}\n".format(self.name, self.authentication, 
                                    self.encryption, self.dh_group, 
                                    self.lifetime_hrs,
                                    self.lifetime_secs)


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

class TunnelInterface:

    def __init__(self, *args, **kwargs):
        self.name = kwargs.get('name')
        self.virtual_router = kwargs.get('virtual_router')
        self.security_zone = kwargs.get('security_zone')
        self.comment = kwargs.get('comment')

    def __str__(self):
        return "Tunnel Interface: \n"\
               "Name: {}\n"\
               "Virtual Router: {}\n"\
               "Security Zone: {}\n".format(self.name,  
                                            self.virtual_router, 
                                            self.security_zone)

class PaloAltoVPN:

    def __init__(self, username, password, ip, ike_profile, ipsec_profile, 
                 ike_gw, ipsec_tunnel, tunnel_interface):
        """
        @param ike_gws
        @type dict 

        @param ipsec_tunnels
        @type list

        @param tunnel_interfaces
        @type dict
        """
        self.username = username
        self.password = password
        self.ip = ip 
        self.fw_dev_hndl = firewall.Firewall(self.ip, self.username, self.password)
        
        self.ike_profile = ike_profile
        self.ipsec_profile = ipsec_profile

        self.ipsec_tunnels = ipsec_tunnel
        self.ike_gws = ike_gw
        self.tunnel_interfaces = tunnel_interface

    def __str__(self):

        return "FW IP: {}\n"\
                "{} \n"\
               "{} \n"\
               "{} \n"\
               "{} \n"\
               "{}\n".format(self.ip, str(self.ike_profile), 
                             str(self.ipsec_profile), 
                             str(self.ike_gws),
                             str(self.tunnel_interfaces),
                             str(self.ipsec_tunnels))

    def create_ike_crypto_profile(self, name="", dh_group=[], authentication=[], 
                                   encryption=[], lifetime_secs=28800, auth_multiple=0):
        """
        Create an IKE Crypto Profile based on the submitted
        parameters.
        """
        self.ike_crypto_prof1 = network.IkeCryptoProfile(name, dh_group, authentication, encryption, lifetime_secs, None, None, None, 
        auth_multiple)
        
        self.fw_dev_hndl.add(self.ike_crypto_prof1) 
        self.ike_crypto_prof1.create()

    def create_ipsec_crypto_profile(self, name="", esp_encryption=[], esp_authentication=[], 
                                    ah_authentication=[], dh_group=[], lifetime_hours=0, lifetime_secs=28800):
        """
        Create an IPSec Crypto Profile based on the submitted 
        parameters.
        """

        if not lifetime_hours:
            self.ipsec_crypto_prof1 = network.IpsecCryptoProfile(name=name, esp_encryption=esp_encryption, esp_authentication=esp_authentication, 
                                                                 ah_authentication=None, 
                                                                 dh_group=dh_group, 
                                                                 lifetime_seconds=lifetime_secs)
        else:
            self.ipsec_crypto_prof1 = network.IpsecCryptoProfile(name=name, esp_encryption=esp_encryption, esp_authentication=esp_authentication, 
                                                                 ah_authentication=None, 
                                                                 dh_group=dh_group, 
                                                                 lifetime_hours=lifetime_hours)
        
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
                                enable_passive_mode=enable_passive_mode, 
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

    def create_tunnel_interface(self, tunnel_name):
        """
        Create a tunnel interface and associate it with a virtual router and security zone
        """
        # Logically create the tunnel interface
        
        tunnel_ref = self.tunnel_interfaces.get(tunnel_name)
        tunnel_intf = network.TunnelInterface(tunnel_ref.name,
                                              comment=tunnel_ref.comment)
        self.fw_dev_hndl.add(tunnel_intf)

        # Retrieve the existing zones 
        fw_zones = network.Zone(tunnel_ref.security_zone)
        self.fw_dev_hndl.add(fw_zones)
        fw_zones.refresh()
        zone_intfs = fw_zones.interface

        # Add interface to the zone 
        zone_intfs.append(tunnel_ref.name)
        
        fw_zones.interface = zone_intfs
        # Retrieve the existing list of virtual routers 

        fw_vrs = network.VirtualRouter(tunnel_ref.virtual_router)
        self.fw_dev_hndl.add(fw_vrs)
        fw_vrs.refresh()
        
        vr_intfs = fw_vrs.interface
        vr_intfs.append(tunnel_ref.name)
        fw_vrs.interface = vr_intfs

        # Push all the configs to the device
        tunnel_intf.create()
        fw_zones.apply()
        fw_vrs.apply()

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
            print vwan_ip
            psk = vpnSiteConnection['connectionConfiguration']['PSK']
            print psk
            az_vwan = AzureManagedVPN(vwan_ip, peer_ip, site_name, 
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
    
    ikgws = {}
    ike_gw_data = fw_data.get('ike_gw')
    for ikgw in ike_gw_data:
        _ike_gw = None
        _ike_gw = IKEGateway(**ikgw)
        ikgws[ikgw.get("name")]= _ike_gw
    

    tuns = {}
    tunnel_intf_data = fw_data.get("tunnel_interface")
    for tintf in tunnel_intf_data:
        _tunnel_interface = None
        _tunnel_interface = TunnelInterface(**tintf)
        tuns[tintf.get("name")] = _tunnel_interface
    

    ipsec_tun_list = []
    ipsec_tunnel_data = fw_data.get('ipsec_tunnel')
    for ipst in ipsec_tunnel_data:
        _ipsec_tunnel = None
        _ipsec_tunnel = IPSecTunnel(ipst.get("ike_gw"), _ipsec_prof.name, **ipst)
        ipsec_tun_list.append(_ipsec_tunnel)

    fw_creds = fw_data.get('creds')

    print("\nCreate a connection with the firewall at: {}\n".format(fw_creds.get('fw_ip')))
    fw_ip = fw_creds.get('fw_ip')
    username = fw_creds.get('username')
    password = fw_creds.get('password')
    pan_vpn_hndl = PaloAltoVPN(username, password, fw_ip, _ike_prof, _ipsec_prof, 
                               ikgws, ipsec_tun_list, tuns)
    return pan_vpn_hndl

def perform_config_validation():
    """
     Purpose is to ensure that HA configurations have the necessary artifacts 
     in terms of tunnel entities etc. 
    """
    pass 

def main():

    if len(sys.argv) != 4:
        print("Usage: %s <palo alto config filename> <azure vpn configuration filename> <registered branch name in azure>",
                sys.argv[0])
        sys.exit(1)
     
    pan_vpn_hndl = parse_fw_configs(sys.argv[1])
    print str(pan_vpn_hndl)
    
    az_data = parse_config_files(sys.argv[2])
    az_vpn_hndl = extract_azure_vpn_config(az_data, sys.argv[3])
    
    print "Establish connection and sync system information from the firewall or panorama device"
    pan_vpn_hndl.fw_dev_hndl.refresh_system_info()

    print "===================================================="
    print "Creating the IKE profile"
    print "===================================================="
    pan_vpn_hndl.create_ike_crypto_profile(pan_vpn_hndl.ike_profile.name,
                                           pan_vpn_hndl.ike_profile.dh_group, 
                                           pan_vpn_hndl.ike_profile.authentication, 
                                           pan_vpn_hndl.ike_profile.encryption)


    print "===================================================="
    print "Creating the IPSec profile"
    print "===================================================="
    pan_vpn_hndl.create_ipsec_crypto_profile(pan_vpn_hndl.ipsec_profile.name, 
                                            pan_vpn_hndl.ipsec_profile.encryption, 
                                            pan_vpn_hndl.ipsec_profile.authentication, 
                                            None, pan_vpn_hndl.ipsec_profile.dh_group, 
                                            pan_vpn_hndl.ipsec_profile.lifetime_hrs,
                                            pan_vpn_hndl.ipsec_profile.lifetime_secs)

    cntr = 0
    for ipsec_tunnel in pan_vpn_hndl.ipsec_tunnels:

        print "===================================================="
        print "Creating the IPSec Tunnel artifacts: {}".format(ipsec_tunnel)
        print "===================================================="

        _cur_ike_gw_name = ipsec_tunnel.ike_gw
        _cur_ike_gw = pan_vpn_hndl.ike_gws.get(_cur_ike_gw_name)
        print "Current IKE GW: {}".format(_cur_ike_gw)

        _cur_tun_name = ipsec_tunnel.tunnel_interface
        _cur_tun_intf = pan_vpn_hndl.tunnel_interfaces.get(_cur_tun_name)
        print "Current tunnel: {}".format(_cur_tun_intf)

        pan_vpn_hndl.create_tunnel_interface(_cur_tun_name)

        wan_ip = None
        if cntr == 0:
            wan_ip = az_vpn_hndl.vwan_ip0
            cntr = cntr + 1
        else:
            wan_ip = az_vpn_hndl.vwan_ip1

        print "===================================================="
        print "Creating the IKE Gateway artifacts: {}".format(wan_ip)
        print "===================================================="
        pan_vpn_hndl.create_ike_gateway(ipsec_tunnel.ike_gw, _cur_ike_gw.protocol_version, 
                                        False, False, 'ip',
                                        wan_ip, _cur_ike_gw.interface, 
                                        'ip', None, 
                                        _cur_ike_gw.auth_type, 
                                        az_vpn_hndl.pre_shared_key, 
                                        _cur_ike_gw.enable_passive_mode, False, 
                                        pan_vpn_hndl.ike_profile.name, 
                                        False, False, True, 5)

        pan_vpn_hndl.create_ipsec_tunnel(ipsec_tunnel.name, 
                                        ipsec_tunnel.tunnel_interface, 
                                        ipsec_tunnel.key_type, 
                                        ipsec_tunnel.ike_gw, 
                                        ipsec_tunnel.ipsec_profile)

    pan_vpn_hndl.fw_dev_hndl.commit(sync=True)

    print("\n\n***********************************")
    print("\nConfiguration successfully applied.")
    print("\n\n***********************************")
if __name__ == "__main__":
    main()