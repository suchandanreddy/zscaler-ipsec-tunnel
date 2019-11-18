import requests
import sys
import json
import os
import time
import logging
from logging.handlers import TimedRotatingFileHandler
import yaml
from jinja2 import Template

requests.packages.urllib3.disable_warnings()

from requests.packages.urllib3.exceptions import InsecureRequestWarning

def get_logger(logfile, level):
    '''
    Create a logger
    '''
    if logfile is not None:

        '''
        Create the log directory if it doesn't exist
        '''

        fldr = os.path.dirname(logfile)
        if not os.path.exists(fldr):
            os.makedirs(fldr)

        logger = logging.getLogger()
        logger.setLevel(level)
 
        log_format = '%(asctime)s | %(levelname)-8s | %(funcName)-20s | %(lineno)-3d | %(message)s'
        formatter = logging.Formatter(log_format)
 
        file_handler = TimedRotatingFileHandler(logfile, when='midnight', backupCount=7)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)

        '''
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        logger.addHandler(console_handler)
        '''

        return logger

    return None


class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        url = base_url + api
        payload = {'j_username' : username, 'j_password' : password}
        
        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            if logger is not None:
                logger.error("No valid JSESSION ID returned\n")
            exit()
       
    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = "https://%s:%s"%(vmanage_host, vmanage_port)
        api = "/dataservice/client/token"
        url = base_url + api      
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return(response.text)
        else:
            return None


class zscaler_api:


    def __init__(self, zscaler_cloud, username, password, api_key):
        self.zscaler_cloud = zscaler_cloud
        self.username = username
        self.password = password
        self.api_key = api_key

    def get_jsessionid(self):

        now = str(int(time.time() * 1000))  
        n = now[-6:]
        r = str(int(n) >> 1).zfill(6)
        key = ""
        for i in range(0, len(n), 1):
            key += self.api_key[int(n[i])]
        for j in range(0, len(r), 1):
            key += self.api_key[int(r[j])+2]
        obfuscatedApiKey = key
        ts = now

        if logger is not None:
            logger.info("OBFUSCATED API KEY / Time: {} / {}".format(obfuscatedApiKey,ts))

        payload = {"username":self.username,"password":self.password,"apiKey":obfuscatedApiKey,"timestamp":ts}

        header = {
                    'content-type': "application/json",
                    'cache-control': "no-cache"
                }

        url = "https://admin.%s/api/v1/authenticatedSession"%(self.zscaler_cloud)
        response = requests.post(url=url, data=json.dumps(payload), headers=header)
        if logger is not None:
            logger.info(response.text)

        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")
            return(jsessionid[0])
        except:
            if logger is not None:
                logger.error("No valid JSESSION ID returned\n")
            exit()

    def activate(self,jsession_id):
        
        headers = {
                    'content-type': "application/json",
                    'cache-control': "no-cache",
                    'cookie': (jsession_id)
                  }

        url = "https://admin.%s/api/v1/status/activate"%(self.zscaler_cloud)
        response = requests.post(url=url,headers=headers)
        if logger is not None:
            logger.info("\nActivate session status " + str(response.text))
        if response.status_code == 200:
            return(response.json())
        else:
            if logger is not None:
                logger.error("\nActivating zscaler changes failed")
            print("\nActivating zscaler changes failed")
            exit()
        
    def get_locations(self,source_ip):

        location_ips_url = "https://pac.%s/getVpnEndpoints?srcIp=%s"%(self.zscaler_cloud,source_ip)

        ip = dict()

        tunnel_dst_ips = requests.get(location_ips_url)

        if tunnel_dst_ips.status_code == 200:
            temp = tunnel_dst_ips.json()
            ip["z_primary"] = temp["primaryIp"]
            ip["z_secondary"] = temp["secondaryIp"]
            if logger is not None:
                logger.info("zscaler ip endpoints are\n" + str(ip))
            return(ip)
        else:
            if logger is not None:
                logger.error("Retrieving zscaler VPN endpoint ip-address failed\n")
            print("\nRetrieving zscaler VPN endpoint ip-address failed")
            exit()
    
    def create_vpn(self,jsession_id,psk,local_id):

        vpn_payload = {
            "type": "UFQDN",
            "fqdn": local_id,
            "comments":"created automatically via API",
            "preSharedKey": psk
        }

        headers = {
            'content-type': "application/json",
            'cache-control': "no-cache",
            'cookie': (jsession_id)
        }

        url = "https://admin.%s/api/v1/vpnCredentials"%(self.zscaler_cloud)
        response = requests.post(url=url, headers=headers, data=json.dumps(vpn_payload))
        vpn = dict()
        if response.status_code == 200:
            data = response.json()
            vpn["id"] = data["id"]
            vpn["fqdn"] = data["fqdn"]
            return(vpn)
        else:
            if logger is not None:
                logger.error("Creating VPN failed " + str(response.text))
            print("\nCreating VPN failed,",response.text)
            exit()

    def create_location(self,jsession_id,vpn,loc_name):
        location_payload = {
                            "name": loc_name,
                            "vpnCredentials": [
                                {
                                "id": vpn["id"],
                                "type": "UFQDN",
                                "fqdn": vpn["fqdn"]
                                }]
                            }

        headers = {
                    'content-type': "application/json",
                    'cache-control': "no-cache",
                    'cookie': (jsession_id)
                  }

        url = "https://admin.%s/api/v1/locations"%(self.zscaler_cloud)
        response = requests.post(url=url, headers=headers, data=json.dumps(location_payload))
        if logger is not None:
            logger.info("\nStatus of location creation " + str(response.text))
        if response.status_code == 200:
            data = response.json()
            return(data)
        else:        
            if logger is not None:
                logger.error("\nCreating Location failed " + str(response.text))
            print("\nCreating Location failed ",response.text)
            exit()

class create_ipsec_tunnel:

    def __init__(self, vmanage_host, vmanage_port, jsessionid, token):
        base_url = "https://%s:%s/dataservice/"%(vmanage_host, vmanage_port)
        self.base_url = base_url
        self.jsessionid = jsessionid
        self.token = token

    def get_interface_ip(self,system_ip,vpn0_source_interface):
        if self.token is not None:
            headers = {'Cookie': self.jsessionid, 'X-XSRF-TOKEN': self.token}
        else:
            headers = {'Cookie': self.jsessionid}

        api = "device/interface?deviceId=%s&vpn-id=0&ifname=%s&af-type=ipv4"%(system_ip,vpn0_source_interface)
        url = self.base_url + api

        response = requests.get(url=url,headers=headers,verify=False)
        if response.status_code == 200:
            try:
                data = response.json()["data"][0]
                ip_address = data["ip-address"].split("/")[0]
                if logger is not None:
                    logger.info("\nsource ip address for tunnels is " + str(ip_address))
                return ip_address
            except Exception as e:
                if logger is not None:
                    logger.error("\nError fetching ip address " + str(e))
                print("\nError fetching ip address",e)
                exit()
    
    def get_device_templateid(self,device_template_name):
        if self.token is not None:
            headers = {'Cookie': self.jsessionid, 'X-XSRF-TOKEN': self.token}
        else:
            headers = {'Cookie': self.jsessionid}
        api = "template/device"
        url = self.base_url + api        
        template_id_response = requests.get(url=url, headers=headers, verify=False)
        device_info = dict()

        if template_id_response.status_code == 200:
            items = template_id_response.json()['data']
            template_found=0
            if logger is not None:
                logger.info("\nFetching Template uuid of %s"%device_template_name)
            print("\nFetching Template uuid of %s"%device_template_name)
            for item in items:
                if item['templateName'] == device_template_name:
                    device_info["device_template_id"] = item['templateId']
                    device_info["device_type"] = item["deviceType"]
                    template_found=1
                    return(device_info)
            if template_found==0:
                if logger is not None:
                    logger.error("\nDevice Template is not found")
                print("\nDevice Template is not found")
                exit()
        else:
            if logger is not None:
                logger.error("\nDevice Template is not found " + str(template_id_response.text))
            print("\nError fetching list of templates")
            exit()


    def get_feature_templates(self,device_template_id):
        if self.token is not None:
            headers = {'Cookie': self.jsessionid, 'X-XSRF-TOKEN': self.token}
        else:
            headers = {'Cookie': self.jsessionid}        

        #Fetching feature templates associated with Device template.
             
        api = "template/device/object/%s"%(device_template_id)
        url = self.base_url + api     
        template_response = requests.get(url=url, headers=headers, verify=False)

        if logger is not None:
            logger.info("\nFetching feature templates")
        print("\nFetching feature templates")

        if template_response.status_code == 200:
            feature_template_ids=template_response.json()
            return(feature_template_ids)
        else:
            print("\nError fetching feature template ids")
            exit()

    def create_ipsec_templates(self,device_info):
            if self.token is not None:
                headers = {'Content-Type': "application/json",'Cookie': self.jsessionid, 'X-XSRF-TOKEN': self.token}
            else:
                headers = {'Content-Type': "application/json",'Cookie': self.jsessionid}

            with open("ipsec-tunnel-json.j2") as f:
                ipsec_int = Template(f.read())

            print("\nCreating IPsec features templates")
            if logger is not None:
                logger.info("\nCreating IPsec features templates")

            
            tunnel_data = dict()
            tunnel_data["template_name"] = "zscaler_ipsec_primary"
            tunnel_data["device_type"] = device_info["device_type"]
            tunnel_data["zscaler_ipsec_if_name"] = "zscaler_ipsec_interface_1"
            tunnel_data["zscaler_ipsec_if_ipv4_address"] = "zscaler_ipsec_ipv4_add_1"
            tunnel_data["zscaler_ipsec_if_tunnel_source_interface"] = "zscaler_ipsec_source_int_1"
            tunnel_data["zscaler_ipsec_if_tunnel_destination"] = "zscaler_ipsec_dst_1"
            tunnel_data["zscaler_ipsec_if_pre_shared_secret"] = "zscaler_ipsec_psk_1"
            tunnel_data["zscaler_ipsec_if_ike_local_id"] = "zscaler_ipsec_ike_local_id_1"
            tunnel_data["zscaler_ipsec_if_ike_remote_id"] = "zscaler_ipsec_ike_remote_id_1"
            
            pri_ipsec_int_payload = ipsec_int.render(config=tunnel_data)

            if logger is not None:
                logger.info("\nPrimary Interface Template payload " + str(pri_ipsec_int_payload))

            api = "template/feature/"
            url = self.base_url + api        
            pri_template_response = requests.post(url=url, data=pri_ipsec_int_payload,headers=headers, verify=False)

            if logger is not None:
                logger.info("\nPrimary Interface Template status code " + str(pri_template_response.status_code))

            if pri_template_response.status_code == 200:
                if logger is not None:
                    logger.info("\nCreated primary ipsec interface template ID: " + str(pri_template_response.json()))
                pri_ipsec_int_template_id = pri_template_response.json()['templateId']
            else:
                if logger is not None:
                    logger.error("\nFailed creating primary ipsec interface template, error: " + str(pri_template_response.text))
                print("\nFailed creating primary ipsec interface template, error: ",pri_template_response.text)
                exit()
            
            tunnel_data["template_name"] = "zscaler_ipsec_secondary"
            tunnel_data["zscaler_ipsec_if_name"] = "zscaler_ipsec_interface_2"
            tunnel_data["zscaler_ipsec_if_ipv4_address"] = "zscaler_ipsec_ipv4_add_2"
            tunnel_data["zscaler_ipsec_if_tunnel_source_interface"] = "zscaler_ipsec_source_int_2"
            tunnel_data["zscaler_ipsec_if_tunnel_destination"] = "zscaler_ipsec_dst_2"
            tunnel_data["zscaler_ipsec_if_pre_shared_secret"] = "zscaler_ipsec_psk_2"
            tunnel_data["zscaler_ipsec_if_ike_local_id"] = "zscaler_ipsec_ike_local_id_2"
            tunnel_data["zscaler_ipsec_if_ike_remote_id"] = "zscaler_ipsec_ike_remote_id_2"

            sec_ipsec_int_payload = ipsec_int.render(config=tunnel_data)
            if logger is not None:
                logger.info("\nPrimary Interface Template payload " + str(sec_ipsec_int_payload))
            sec_template_response = requests.post(url=url, data=sec_ipsec_int_payload,headers=headers, verify=False)

            if sec_template_response.status_code == 200:
                if logger is not None:
                    logger.info("\nCreated primary ipsec interface template ID: " + str(sec_template_response.json()))
                sec_ipsec_int_template_id = sec_template_response.json()['templateId']
            else:
                print("\nFailed creating secondary ipsec interface template, error: ",sec_template_response.text)
                exit()

            pri_ipsec_int_template = {
                                       "templateId": pri_ipsec_int_template_id,
                                       "templateType": "vpn-vedge-interface-ipsec",
                                     }

            sec_ipec_int_template = {
                                        "templateId":sec_ipsec_int_template_id,
                                        "templateType": "vpn-vedge-interface-ipsec"
                                    }

            ipsec_int_template = [pri_ipsec_int_template,sec_ipec_int_template]
            
            return(ipsec_int_template)
            
    def push_device_template(self,device_info,ipsec_templateid,ipsec_parameters,feature_template_ids):
        
        if self.token is not None:
            headers = {'Content-Type': "application/json",'Cookie': self.jsessionid, 'X-XSRF-TOKEN': self.token}
        else:
            headers = {'Content-Type': "application/json",'Cookie': self.jsessionid}
        device_template_id = device_info["device_template_id"]
        api = "template/device/%s"%device_template_id
        url = self.base_url + api

        feature_template_list = feature_template_ids["generalTemplates"]

        for item in feature_template_list:
            if item["templateType"] == "vpn-vedge":
                sub_templates = item["subTemplates"]
                sub_templates.append(ipsec_templateid[0])
                sub_templates.append(ipsec_templateid[1])
                break
            
        payload = {
                    "templateId":device_template_id,"templateName":device_template_name,
                    "templateDescription":feature_template_ids["templateDescription"],
                    "deviceType":feature_template_ids["deviceType"],
                    "configType":"template","factoryDefault":False,
                    "policyId":feature_template_ids["policyId"],
                    "featureTemplateUidRange":[],"connectionPreferenceRequired":True,
                    "connectionPreference":True,"policyRequired":True,
                    "generalTemplates":feature_template_ids["generalTemplates"],
                  }
        payload = json.dumps(payload)

        if logger is not None:
            logger.info("\nDevice template JSON payload " + str(payload))
        device_template_edit_res = requests.put(url=url,data=payload,headers=headers,verify=False)

        if device_template_edit_res.status_code == 200:
            items = device_template_edit_res.json()['data']['attachedDevices']
            device_uuid = list()
            for i in range(len(items)):
                device_uuid.append(items[i]['uuid'])
        else:
            print("\nError editing device template\n")
            print(device_template_edit_res.text)
            exit()

        if logger is not None:
            logger.info("\nDevice uuid: %s"%device_uuid)
        print("\nDevice uuid: %s"%device_uuid)

        # Fetching Device csv values
        if logger is not None:
            logger.info("\nFetching device csv values")
        print("\nFetching device csv values")

        payload = { 
                    "templateId":device_template_id,
                    "deviceIds":device_uuid,
                    "isEdited":True,
                    "isMasterEdited":True
                  }
        payload = json.dumps(payload)
        
        api = "template/device/config/input/"
        url = self.base_url + api
        device_csv_res = requests.post(url=url, data=payload,headers=headers, verify=False)

        if device_csv_res.status_code == 200:
            device_csv_values = device_csv_res.json()['data']
        else:
            if logger is not None:
                logger.error("\nError getting device csv values" + str(device_csv_res.text))
            print("\nError getting device csv values")
            exit()

        # Adding the values to device specific variables

        temp = device_csv_values

        for item1 in temp:
            sys_ip = item1["csv-deviceIP"]
            for item2 in ipsec_parameters:
                if sys_ip == item2["device_sys_ip"]:
                    item1["/0/zscaler_ipsec_interface_1/interface/if-name"] = "ipsec1"
                    item1["/0/zscaler_ipsec_interface_1/interface/ip/address"] = "10.10.10.1/30"
                    item1["/0/zscaler_ipsec_interface_1/interface/tunnel-source-interface"] = item2["vpn0_source_interface"]
                    item1["/0/zscaler_ipsec_interface_1/interface/tunnel-destination"] = item2["zscaler_primary_dst_ip"]
                    item1["/0/zscaler_ipsec_interface_1/interface/ike/authentication-type/pre-shared-key/pre-shared-secret"] = item2["pre_shared_key"]
                    item1["/0/zscaler_ipsec_interface_1/interface/ike/authentication-type/pre-shared-key/ike-local-id"] = item2["local_id"]
                    item1["/0/zscaler_ipsec_interface_1/interface/ike/authentication-type/pre-shared-key/ike-remote-id"] = item2["zscaler_primary_dst_ip"]
                    item1["/0/zscaler_ipsec_interface_2/interface/if-name"] = "ipsec2"
                    item1["/0/zscaler_ipsec_interface_2/interface/ip/address"] = "10.10.10.5/30"
                    item1["/0/zscaler_ipsec_interface_2/interface/tunnel-source-interface"] = item2["vpn0_source_interface"]
                    item1["/0/zscaler_ipsec_interface_2/interface/tunnel-destination"] = item2["zscaler_secondary_dst_ip"]
                    item1["/0/zscaler_ipsec_interface_2/interface/ike/authentication-type/pre-shared-key/pre-shared-secret"] = item2["pre_shared_key"]
                    item1["/0/zscaler_ipsec_interface_2/interface/ike/authentication-type/pre-shared-key/ike-local-id"] = item2["local_id"]
                    item1["/0/zscaler_ipsec_interface_2/interface/ike/authentication-type/pre-shared-key/ike-remote-id"] = item2["zscaler_secondary_dst_ip"]                   
                    break
                else:
                    continue

        if logger is not None:
            logger.info("\nUpdated device csv values are" + str(temp))
        device_csv_values = temp

        # Attaching new Device template

        print("\nAttaching new device template")
        if logger is not None:
            logger.info("\nAttaching new device template")

        payload = { 
                    "deviceTemplateList":[
                    {
                        "templateId":device_template_id,
                        "device":device_csv_values,
                        "isEdited":True,
                        "isMasterEdited":False
                    }]
                  }
        payload = json.dumps(payload)

        api = "template/device/config/attachfeature"
        url = self.base_url + api
        attach_template_res = requests.post(url=url, data=payload,headers=headers, verify=False)


        if attach_template_res.status_code == 200:
            attach_template_pushid = attach_template_res.json()['id']
        else:
            if logger is not None:
                logger.error("\nAttaching device template failed, "+str(attach_template_res.text))
            print("\nAttaching device template failed")
            exit()

        # Fetch the status of template push

        api = "device/action/status/%s"%attach_template_pushid
        url = self.base_url + api        

        while(1):
            template_status_res = requests.get(url,headers=headers,verify=False)
            if template_status_res.status_code == 200:
                if template_status_res.json()['summary']['status'] == "done":
                    print("\nTemplate push status is done")
                    if logger is not None:
                        logger.info("\nTemplate push status is done")
                    return
            else:
                if logger is not None:
                    logger.error("\nFetching template push status failed " + str(template_status_res.text))                
                print("\nFetching template push status failed")
                exit()

if __name__ == "__main__":
    try:
        log_level = logging.DEBUG
        logger = get_logger("log/ipsec_logs.txt", log_level)
        if logger is not None:
            logger.info("Loading configuration details from YAML\n")
            print("Loading configuration details from YAML\n")
        with open("config_details.yaml") as f:
            config = yaml.safe_load(f.read())
        
        vmanage_host = config["vmanage_host"]
        vmanage_port = config["vmanage_port"]
        vmanage_username = config["vmanage_username"]
        vmanage_password = config["vmanage_password"]
        device_template_name = config["device_template_name"]

        zscaler_cloud = config["zscaler_cloud"]
        api_key = config["api_key"]
        zscaler_username = config["zscaler_username"]
        zscaler_password = config["zscaler_password"]
        
        Auth = Authentication()
        jsessionid = Auth.get_jsessionid(vmanage_host,vmanage_port,vmanage_username,vmanage_password)
        token = Auth.get_token(vmanage_host,vmanage_port,jsessionid)
        ipsec_tunnel = create_ipsec_tunnel(vmanage_host,vmanage_port,jsessionid, token)
        zscaler_config = zscaler_api(zscaler_cloud,zscaler_username,zscaler_password,api_key)
        z_jsession_id = zscaler_config.get_jsessionid()
        ipsec_parameters = list()
        if logger is not None:
            logger.info(z_jsession_id)
        # Loop over edge routers to create and deploy ipsec tunnel to zscaler vpn endpoint
        for device in config["devices"]:
            print("Device: {}".format(device["system_ip"]))
            source_ip = ipsec_tunnel.get_interface_ip(device["system_ip"],device["vpn0_source_interface"])

            psk = device["psk"]
            local_id = device["local_id"]
            loc_name = device["location_name"]

            locations = zscaler_config.get_locations(source_ip)
            if logger is not None:
                logger.info(locations)
            print("\nRetrieved Zscaler VPN endpoint IP addresses")
            vpn = zscaler_config.create_vpn(z_jsession_id,psk,local_id)
            if logger is not None:
                logger.info(vpn)
            print("\nCreated Zscaler VPN endpoints")
            location = zscaler_config.create_location(z_jsession_id,vpn,loc_name)
            if logger is not None:
                logger.info(locations)
            print("\nCreated locations and binded them to Zscaler VPN end points")

            activate_status = zscaler_config.activate(z_jsession_id)

            if logger is not None:
                logger.info(activate_status)

            print("\nActivated Zscaler changes")

            temp_parameters =  { 
                                 "device_sys_ip":device["system_ip"],
                                 "zscaler_primary_dst_ip": locations['z_primary'],
                                 "zscaler_secondary_dst_ip": locations['z_secondary'],
                                 "local_id": local_id,
                                 "vpn0_source_interface": device["vpn0_source_interface"],
                                 "pre_shared_key": psk,
                               }

            ipsec_parameters.append(temp_parameters)

            if logger is not None:
                logger.info("\nTunnel parameters are " + str(ipsec_parameters))

        device_info = ipsec_tunnel.get_device_templateid(device_template_name)
            
        feature_templateids = ipsec_tunnel.get_feature_templates(device_info["device_template_id"])

        ipsec_templateid = ipsec_tunnel.create_ipsec_templates(device_info)
            
        ipsec_tunnel.push_device_template(device_info,ipsec_templateid,ipsec_parameters,feature_templateids)

    except Exception as e:
        print(e)


