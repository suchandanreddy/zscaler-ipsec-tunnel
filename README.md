# Zscaler IPsec tunnel

# Objective 

*   How to use Zscaler APIs to create VPN endpoints and locations.
*   How to use vManage REST APIs to configure IPsec tunnel from  vEdge router to Zscaler VPN endpoints. 


# Requirements

To use this code you will need:

* Python 3.7+
* vManage user login details. (User should have privilege level to configure feature templates and edit device template)
* vEdge routers with device template attached.
* Zscaler login and API key details. (User should be part of partner admin group)
* Refer https://help.zscaler.com/zia/api-getting-started for documentation on how to enable API subscription for your Zscaler account

# Install and Setup

- Clone the code to local machine.

```
git clone https://github.com/suchandanreddy/zscaler-ipsec-tunnel.git
cd zscaler-ipsec-tunnel
```
- Setup Python Virtual Environment (requires Python 3.7+)

```
python3.7 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

- Create config_details.yaml using below sample format to update the environment variables for vManage, Zscaler login details and tunnel parameters

## Example:

```
# vManage Connectivity Info
vmanage_host: 
vmanage_port: 
vmanage_username: 
vmanage_password: 


# Zscaler Connectivity Info
zscaler_cloud: 
api_key: 
zscaler_username: 
zscaler_password:

# Device template Info

device_template_name:

# Device model type is cedge or vedge based on router platform

device_model_type:  

# IPsec route prefix for all Service VPNs

#service_vpn_ipsec_route:  0.0.0.0/0

# Network Routers
devices:
  - system_ip: 
    vpn0_source_interface: 
    #local_id_domain: cisco.com

#dummy /30 private ip address for IPsec tunnel

    #pri_ipsec_ip: 10.10.10.1/30
    #sec_ipsec_ip: 10.10.10.5/30
    #pri_ipsec_id: ipsec254
    #sec_ipsec_id: ipsec255
    #psk: ""
    #local_id: ""
    #location_name: ""

  - system_ip: 
    vpn0_source_interface: 
    #local_id_domain: viptela.com

#dummy /30 private ip address for IPsec tunnel

    #pri_ipsec_ip: 10.10.10.1/30
    #sec_ipsec_ip: 10.10.10.5/30
    #pri_ipsec_id: ipsec254
    #sec_ipsec_id: ipsec255
    #psk: ""
    #local_id: ""
    #location_name: ""
```

After setting the env variables, run the python script `zscaler-ipsec-tunnel.py`

`zscaler-ipsec-tunnel.py` script does the below steps in sequence. 

## Workflow

### Automation using vManage APIs:

- Get source ip address of the tunnel source interface on vEdge Routers

### Automation using Zscaler APIs: 

- Using the tunnel source ip address, retrieve the nearest zscaler cloud endpoint IP addresses using the zscaler API `/pac.<zscaler-cloud-name>/getVpnEndpoints?srcIp=`
- Create VPN endpoint on zscaler using API `/admin.<zscaler-cloud-name>/api/v1/vpnCredentials`
- Create location using API `/admin.<zscaler-cloud-name>/api/v1/locations` and bind it to the VPN endpoint created in above step. 
- Default location name is `hostname + location city name based on Public IP`
- Default local id is `hostname + uuid + @cisco.com`
- Zscaler VPN endpoints and locations are created for IPsec tunnels from each vEdge router

### Automation using vManage APIs:

- Fetch the device template-id associated with the device template name. 
- Retrieve feature templates associated with this device template. 
- Create 2 IPsec feature templates with device specific variables for Zscaler primary and secondary tunnels.
- Attach the new IPsec feature templates to device templates. 
- Add the device specific variables values for IPsec tunnel source interface, tunnel ip address, tunnel destination address, local-id, remote-id, pre-shared key.
- Push the updated template to all the devices attached to the Device template.
- By end of the script, 2 zscaler tunnels(primary and secondary) would be configured to the nearest Zscaler VPN endpoint from each vEdge router which is attached to the device template. 
- Create IPsec route in all service VPNs. By default we create default IPsec route in service VPN but destination prefix for IPsec route can be modified using variable `service_vpn_ipsec_route` in config_details.yaml

## Restrictions

- Default dummy IP addresses used for tunnels are 10.10.10.1/30 (for primary) and 10.10.10.5/30 (for secondary) , can be changed using `config_details.yaml` variables `pri_ipsec_ip` and `sec_ipsec_ip` if there is overlapping address with other interfaces in VPN 0
- vEdge should be in vManage mode with device template attached which contains VPN 0 feature template and at least one VPN 0 interface which can be used as source interface for the IPsec tunnel. 
- Script creates IPsec feature templates with names **Device Template name** + `_zscaler_ipsec_primary` and **Device Template name** + `_zscaler_ipsec_secondary` so, there shouldn't pre-configured IPsec feature templates with this name. If needed, we can change the code to create IPsec feature templates with alternative name. 

## Sample output

```
(venv) msuchand@MSUCHAND-M-Q1FH zscaler-ipsec-tunnel % python3 zscaler-ipsec-tunnel.py

Loading configuration details from YAML

Creating Zscaler VPN and location for device: 1.1.1.7

Retrieved Zscaler VPN endpoint IP addresses

Created Zscaler VPN endpoints

Created locations and binded them to Zscaler VPN end points

Activated Zscaler changes

Creating Zscaler VPN and location for device: 1.1.1.8

Source interface ip address is 10.20.20.1 so seems device is behind NAT!!

Please enter NAT Public IP address so that we can find nearest Zscaler location:<Public IP address>

Retrieved Zscaler VPN endpoint IP addresses

Created Zscaler VPN endpoints

Created locations and binded them to Zscaler VPN end points

Activated Zscaler changes

Successfully deleted Zscaler API session

Fetching Template uuid of DC-vedges

Fetching feature templates

Creating IPsec features templates

Device uuid: ['4ea1260d-3a3f-479b-bfaa-9bd3181bbdd5', 'db5f5e7d-f3e3-4c46-9f60-438ab5fdaacf']

Fetching device csv values

Attaching new device template

Updated IPsec templates successfully

Service VPN Templates list ['1661884f-b9a1-4d18-91a8-f6ba6798a1b5', 'b09cb27f-970c-4ba5-95e1-58817ed3f1b2']

Updated Service VPN template 1661884f-b9a1-4d18-91a8-f6ba6798a1b5 successfully

Updated Service VPN template b09cb27f-970c-4ba5-95e1-58817ed3f1b2 successfully
```