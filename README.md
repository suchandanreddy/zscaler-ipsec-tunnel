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

# Network Routers
devices:
  - system_ip: 
    vpn0_source_interface: 
    psk: 
    local_id: 
    location_name: 
  - system_ip: 
    vpn0_source_interface: 
    psk: 
    local_id: 
    location_name: 
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
- Zscaler VPN endpoints and locations are created for IPsec tunnels from each vEdge router

### Automation using vManage APIs:

- Fetch the device template-id associated with the device template name. 
- Retrieve feature templates associated with this device template. 
- Create 2 IPsec feature templates with device specific variables for Zscaler primary and secondary tunnels.
- Attach the new IPsec feature templates to device templates. 
- Add the device specific variables values for IPsec tunnel source interface, tunnel ip address, tunnel destination address, local-id, remote-id, pre-shared key.
- Push the updated template to all the devices attached to the Device template.
- By end of the script, 2 zscaler tunnels(primary and secondary) would be configured to the nearest Zscaler VPN endpoint from each vEdge router which is attached to the device template. 

## Restrictions

- vEdge should be in vManage mode with device template attached which contains VPN 0 feature template and at least one VPN 0 interface which can be used as source interface for the IPsec tunnel. 
- Script creates IPsec feature templates with names `zscaler_ipsec_primary` and `zscaler_ipsec_secondary` so, there shouldn't pre-configured IPsec feature templates with this name. If needed, we can change the code to create IPsec feature templates with alternative name. 

## Sample output

```
$ python3 zscaler-ipsec-tunnel.py 

Loading configuration details from YAML

Device: 1.1.1.7

Retrieved Zscaler VPN endpoint IP addresses

Created Zscaler VPN endpoints

Created locations and binded them to Zscaler VPN end points

Activated Zscaler changes

Device: 1.1.1.8

Retrieved Zscaler VPN endpoint IP addresses

Created Zscaler VPN endpoints

Created locations and binded them to Zscaler VPN end points

Activated Zscaler changes

Fetching Template uuid of DC-vedges

Fetching feature templates

Creating IPsec features templates

Device uuid: ['4ea1260d-3a3f-479b-bfaa-9bd3181bbdd5', 'db5f5e7d-f3e3-4c46-9f60-438ab5fdaacf']

Fetching device csv values

Attaching new device template

Template push status is done
```