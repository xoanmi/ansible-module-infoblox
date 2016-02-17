#!/usr/bin/python
#
#

DOCUMENTATION = '''
'''

EXAMPLES = '''
'''

import json
import re
import requests
requests.packages.urllib3.disable_warnings()

# ---------------------------------------------------------------------------
# Infoblox
# ---------------------------------------------------------------------------
class Infoblox(object):
    '''
    Class for manage all the REST API calls with the Infoblox appliances
    '''

    def __init__(self, module, host , user, password, api_version, dns_view, net_view):

        self.module = module
        self.host = host
        self.user = user
        self.password = password
        self.api_version = api_version
        self.dns_view = dns_view
        self.net_view = net_view

    def get_host_by_search(self, host):
        '''
        Search host by FQDN in infoblox by useing rest api
        '''

        rest_url = "https://{self.host}/wapi/v{self.api_version}/record:host?name~={host}&view={self.dns_view}".format(self=self, host=host)
        r = requests.get(url=rest_url, auth=(self.user, self.password), verify=False)
        if r.status_code == 200:
            data = r.json()
            if data:
                return data
            elif 'text' in data:
                raise Exception(data['text'])
            else:
                return False
        else:
            r.raise_for_status()

    def create_host_record(self, address, host):
        '''
        Add host in infoblox by useing rest api:
            - If address is IP address use it to add host
            - If address is NET in CIDR format search next available IP in these network and use it to add host
        '''

        network = ""
        ipv4addr = ""

        if re.match("^(((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)(/(3[012]|[12]?[0-9])))+$", address):
            network = str(address)
        elif re.match("(((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?))+$", address):
            ipv4addr = str(address)
        else:
            raise Exception(msg="Expected IP or NET address in CIDR format")

        rest_url = "https://{self.host}/wapi/v{self.api_version}/record:host?_return_fields=ipv4addrs".format(self=self)

        if network:
            payload = {"ipv4addrs": [{"ipv4addr": "func:nextavailableip:"+network}],"name": host, "view":self.dns_view}
        elif ipv4addr:
            payload = {"ipv4addrs": [{"ipv4addr":ipv4addr}],"name": host, "view":self.dns_view}
        else:
            raise Exception(msg="Error forming payload")

        r = requests.post(url=rest_url, auth=(self.user, self.password), verify=False, json=payload)
        data = r.json()
        if r.status_code == 200 or r.status_code == 201:
            return data
        elif 'text' in data:
            raise Exception(data['text'])
        else:
            r.raise_for_status()

    def delete_host_record(self, host):
        '''
        Delete host in infoblox by useing rest api:
        '''

        rest_url = "https://{self.host}/wapi/v{self.api_version}/record:host?name={host}&view={self.dns_view}".format(self=self, host=host)

        r = requests.get(url=rest_url, auth=(self.user, self.password), verify=False)
        data = r.json()
        if r.status_code == 200:
            host_ref = data[0]['_ref']
            if host_ref and re.match("record:host\/[^:]+:([^\/]+)\/", host_ref).group(1) == host:
                rest_url = 'https://' + self.host + '/wapi/v' + self.api_version + '/' + host_ref
                r = requests.delete(url=rest_url, auth=(self.user, self.password), verify=False)
                if r.status_code == 200:
                    msg="Object %s deleted" % (host)
                    return  msg
                else:
                    r.raise_for_status()
            else:
                raise Exception("Received unexpected host reference: %s" % host_ref)
        else:
            raise Exception("Host not found: %s" % host)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    '''
    Ansible module to manage infoblox opeartion by useing rest api
    '''
    module = AnsibleModule(
        argument_spec=dict(
            username    = dict(required=True),
            password    = dict(required=True),
            host        = dict(required=True),
            address     = dict(required=False, default=False),
            ib_server   = dict(required=False, default='192.168.0.1'),
            api_version = dict(required=False, default='1.7.1'),
            dns_view    = dict(required=False, default='Private'),
            net_view    = dict(required=False, default='default'),
            option      = dict(required=False, default='get', choices=['get', 'add','delete']),
        ),
        supports_check_mode=True,
    )

    '''
    Global vars
    '''
    username    = module.params["username"]
    password    = module.params["password"]
    host        = module.params["host"]
    address     = module.params["address"]
    ib_server   = module.params["ib_server"]
    api_version = module.params["api_version"]
    dns_view    = module.params["dns_view"]
    net_view    = module.params["net_view"]
    option      = module.params["option"]

    try:
        infoblox = Infoblox(module, ib_server, username, password, api_version, dns_view, net_view)

        if option == 'get':
            result = infoblox.get_host_by_search(host)
            if result:
            #       address = []
            #       for i in result[0]['ipv4addrs']:
            #           address.append(i['ipv4addr'])
            #       module.exit_json(host_found=True, hostname=result[0]['name'], address=address, ref=result[0]['_ref'])

                for d in result:
                    data = json.dumps(d)

                module.exit_json(host_found=True, data=data)

            else:
                module.exit_json(host_found=False, msg="Host %s not found" % host)

        elif option == 'add':
            if address:
                result = infoblox.create_host_record(address, host)
                module.exit_json(changed=True, host_added=True, hostname=result['ipv4addrs'][0]['host'], address=result['ipv4addrs'][0]['ipv4addr'], ref=result['_ref'])
            else:
                raise Exception("Option 'address' needed to add a host")
        elif option == 'delete':
            result = infoblox.get_host_by_search(host)
            if result:
                result = infoblox.delete_host_record(host)
                module.exit_json(changed=True, hostname=host, msg=result)
            else:
                raise Exception("Host %s not found" % host)

    except Exception as err:
        module.fail_json(msg=str(err))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
