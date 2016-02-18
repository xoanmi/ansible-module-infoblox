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

    def __init__(self, module, ib_server, username, password, api_version, dns_view):

        self.module = module
	self.dns_view = dns_view
        self.base_url = "https://{host}/wapi/v{version}/".format(host=ib_server, version=api_version)
        self.auth = (username, password)

    def invoke(self, method, tail, ok_codes=(200,), **params):
        request = getattr(requests, method)
        response = request(self.base_url + tail, auth=self.auth, verify=False, **params)
        if response.status_code not in ok_codes:
            response.raise_for_status()
        payload = response.json()
        if isinstance(payload, dict) and 'text' in payload:
            raise Exception(payload['text'])
        return payload

    def get_host_by_search(self, host):
        '''
        Search host by FQDN in infoblox by useing rest api
        '''

        return self.invoke('get', "record:host", params={'name~': host, 'view': self.dns_view})

    def create_host_record(self, network, host):
        '''
        Add host in infoblox by useing rest api:
            - If address is NET in CIDR format search next available IP in these network and use it to add host
        '''

        if re.match("^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/(3[0-2]|[1-2]?[0-9])$", network):
            pass
        else:
            raise Exception(msg="Expected NET address in CIDR format")

        payload = {"ipv4addrs": [{"ipv4addr": "func:nextavailableip:"+network}],"name": host, "view":self.dns_view}
        return self.invoke('post', "record:host?_return_fields=ipv4addrs", ok_codes=(200, 201, 400), json=payload)

    def delete_host_record(self, host):
        '''
        Delete host in infoblox by useing rest api:
        '''

        data = self.invoke('get', "record:host", params={'name': host, 'view': self.dns_view})
        host_ref = data[0]['_ref']
        m = re.match(r"record:host/[^:]+:([^/]+)/", host_ref)
        if m and m.group(1) == host:
            self.invoke('delete', host_ref)
            return "Object %s deleted" % host
        else:
            raise Exception("Received unexpected host reference: %s" % host_ref)


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
            network     = dict(required=False, default=False),
            ib_server   = dict(required=False, default='192.168.0.1'),
            api_version = dict(required=False, default='1.7.1'),
            dns_view    = dict(required=False, default='Private'),
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
    network     = module.params["network"]
    ib_server   = module.params["ib_server"]
    api_version = module.params["api_version"]
    dns_view    = module.params["dns_view"]
    option      = module.params["option"]

    try:
        infoblox = Infoblox(module, ib_server, username, password, api_version, dns_view)

        if option == 'get':
            result = infoblox.get_host_by_search(host)
            if result:
                module.exit_json(host_found=True, result=result)

            else:
                module.exit_json(host_found=False, msg="Host %s not found" % host)

        elif option == 'add':
            if network:
                result = infoblox.create_host_record(network, host)
                module.exit_json(changed=True, host_added=True, result=result)
            else:
                raise Exception("Option 'address' needed to add a host")
        elif option == 'delete':
            result = infoblox.get_host_by_search(host)
            if result:
                result = infoblox.delete_host_record(host)
                module.exit_json(changed=True, hostname=host, result=result)
            else:
                raise Exception("Host %s not found" % host)

    except Exception as err:
        module.fail_json(msg=str(err))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
