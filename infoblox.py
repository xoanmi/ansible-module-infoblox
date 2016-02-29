#!/usr/bin/python
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
module: infoblox
short_description: manage Infoblox via Web API
description:
  - Manage Infoblox IPAM and DNS via Web API
version_added: "2.1"
author:
  - "Joan Miquel Luque"
requirements:
  - "requests >= 2.9.1"
options:
  server:
    description:
      - Infoblox IP/URL
    required: True
  username:
    description:
      - Infoblox username
      - The user must have API privileges
    required: True
  password:
    description:
      - Infoblox password
    required: True
  action:
    description:
      - Action to perform
    required: True
    choices: ['get_host', 'get_network', 'get_next_available_ip', 'add_host','delete_host', 'set_extattr']
  host:
    description:
      - Hostname variable to search, add or delete host object
      - The hostname must be in fqdn format
    requiered: False
  network:
    description:
      - Network address
      - Must be indicated as a CDIR format or 192.168.1.0 format
    required: False
    default: False
  address:
    description:
      - IP Address
    required: False
    default: False
  attr_name:
    description:
      - Extra Attribute name
    required: False
  attr_value:
    description:
      - Extra Attribute value
    required: False
  comment:
    description:
      - Object comment
      - This comment will be added when the module create any object
    required: False
    default: "Object managed by ansible-infoblox module"
  api_version:
    description:
      - Infoblox Web API user to perfom actions
    required: False
    default: "1.7.1"
  dns_view:
    description:
      - Infoblox DNS View
    required: False
    default: "Private"
  net_view:
    description:
      - Infoblox Network View
    required: False
    default: "default"
'''

EXAMPLES = '''
---
 - hosts: localhost
    connection: local
       gather_facts: False

  tasks:
  - name: Add host
    infoblox:
      server=192.168.1.1
      username=admin
      password=admin
      action=add_host
      network=192.168.1.0/24
      host={{ item }}
    with_items:
      - test01.local
      - test02.local
    register: infoblox

  - name: Do awesome stuff with the result
    debug: msg="Get crazy!"
'''

try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ---------------------------------------------------------------------------
# Infoblox
# ---------------------------------------------------------------------------
class Infoblox(object):
    '''
    Class for manage all the REST API calls with the Infoblox appliances
    '''
    def __init__(self, module, server, username, password, api_version, dns_view, net_view):

        self.module = module
        self.dns_view = dns_view
        self.net_view = net_view
        self.auth = (username, password)
        self.base_url = "https://{host}/wapi/v{version}/".format(host=server, version=api_version)

    def invoke(self, method, tail, ok_codes=(200,), **params):
        '''
        Perform the HTTPS request by useing rest api
        '''
        request = getattr(requests, method)
        response = request(self.base_url + tail, auth=self.auth, verify=False, **params)

        if response.status_code not in ok_codes:
            response.raise_for_status()
        else:
            payload = response.json()

        if isinstance(payload, dict) and 'text' in payload:
            raise Exception(payload['text'])
        else:
            return payload

    # ---------------------------------------------------------------------------
    # get_network()
    # ---------------------------------------------------------------------------
    def get_network(self, network):
        '''
        Search network in infoblox by useing rest api
        Network format supported:
            - 192.168.1.0
            - 192.168.1.0/24
        '''
        if not network:
            self.module.exit_json(msg="You must specify the option 'network'.")
        return self.invoke('get', "network", params={'network' : network, 'network_view' : self.net_view})

    # ---------------------------------------------------------------------------
    # get_next_available_ip()
    # ---------------------------------------------------------------------------
    def get_next_available_ip(self, network_ref):
        '''
        Return next available ip in a network range
        '''
        if not network_ref:
            self.module.exit_json(msg="You must specify the option 'network_ref'.")
        return self.invoke('post', network_ref, ok_codes=(200,), params={'_function' : 'next_available_ip'})

    # ---------------------------------------------------------------------------
    # get_host_by_name()
    # ---------------------------------------------------------------------------
    def get_host_by_name(self, host):
        '''
        Search host by FQDN in infoblox by useing rest api
        '''
        if not host:
            self.module.exit_json(msg="You must specify the option 'host'.")
        return self.invoke('get', "record:host", params={'name': host, '_return_fields+' : 'comment,extattrs' ,'view': self.dns_view})

    # ---------------------------------------------------------------------------
    # create_host_record()
    # ---------------------------------------------------------------------------
    def create_host_record(self, host, network, address, comment):
        '''
        Add host in infoblox by useing rest api
        '''
        if not host:
            self.module.exit_json(msg="You must specify the option 'host'.")
        if network:
            payload = {"ipv4addrs": [{"ipv4addr": "func:nextavailableip:"+network}],"name": host, "view":self.dns_view, "comment": comment}
        elif address:
            payload = {"name": host ,"ipv4addrs":[{"ipv4addr": address}],"view":self.dns_view, "comment": comment}
        else:
            raise Exception("Function options missing!")

        return self.invoke('post', "record:host?_return_fields=ipv4addrs", ok_codes=(200, 201, 400), json=payload)

    # ---------------------------------------------------------------------------
    # delete_host_record()
    # ---------------------------------------------------------------------------
    def delete_host_record(self, host):
        '''
        Delete host in infoblox by useing rest api
        '''
        if not host:
            self.module.exit_json(msg="You must specify the option 'host'.")
        data = self.invoke('get', "record:host", params={'name': host, 'view': self.dns_view})
        host_ref = data[0]['_ref']
        m = re.match(r"record:host/[^:]+:([^/]+)/", host_ref)
        if m and m.group(1) == host:
            self.invoke('delete', host_ref)
            return "Object %s deleted" % host
        else:
            raise Exception("Received unexpected host reference: %s" % host_ref)

    # ---------------------------------------------------------------------------
    # set_extattr()
    # ---------------------------------------------------------------------------
    def set_extattr(self, object_ref,  attr_name, attr_value):
        '''
        Update the extra attribute value
        '''
        if not object_reft:
            self.module.exit_json(msg="You must specify the option 'object_red'.")
        payload = { "extattrs": { attr_name: { "value" : attr_value }}}
        return self.invoke('put', object_ref, json=payload)


# ---------------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------------

def main():
    '''
    Ansible module to manage infoblox opeartion by useing rest api
    '''
    module = AnsibleModule(
        argument_spec=dict(
            server      = dict(required=True),
            username    = dict(required=True),
            password    = dict(required=True),
            action      = dict(required=True, choices=['get_host', 'get_network', 'get_next_available_ip', 'add_host','delete_host', 'set_extattr']),
            host        = dict(required=False),
            network     = dict(required=False, default=False),
            address     = dict(required=False, default=False),
            attr_name   = dict(required=False),
            attr_value  = dict(required=False),
            comment     = dict(required=False, default="Object managed by ansible-infoblox module"),
            api_version = dict(required=False, default='1.7.1'),
            dns_view    = dict(required=False, default='Private'),
            net_view    = dict(required=False, default='default'),
        ),
        mutually_exclusive=[
            ['network', 'address']
            ],
        required_together=[
            ['attr_name','attr_value']
            ],
        supports_check_mode=True,
    )

    if not HAS_REQUESTS:
         module.fail_json(msg="Library 'requests' is required. Use 'sudo pip install requests' to fix it.")

    '''
    Global vars
    '''
    server      = module.params["server"]
    username    = module.params["username"]
    password    = module.params["password"]
    action      = module.params["action"]
    host        = module.params["host"]
    network     = module.params["network"]
    address     = module.params["address"]
    attr_name   = module.params["attr_name"]
    attr_value  = module.params["attr_value"]
    comment     = module.params["comment"]
    api_version = module.params["api_version"]
    dns_view    = module.params["dns_view"]
    net_view    = module.params["net_view"]

    try:
        infoblox = Infoblox(module, server, username, password, api_version, dns_view, net_view)

        if action == 'get_network':
            if network:
                result = infoblox.get_network(network)
                if result:
                    module.exit_json(host_found=True, result=result)
                else:
                    module.exit_json(host_found=False, msg="Network %s not found" % network)
            else:
                raise Exception("You must specify the option 'network' or 'address'.")

        elif action == 'get_next_available_ip':
            result = infoblox.get_network(network)
            if result:
                network_ref = result[0]['_ref']
                result = infoblox.get_next_available_ip(network_ref)
                if result:
                    module.exit_json(ip_available=True, result=result)
                else:
                    module.fail_json(msg="No vailable IPs in network: %s" % network)

        elif action == 'get_host':
            result = infoblox.get_host_by_name(host)
            if result:
                module.exit_json(host_found=True, result=result)
            else:
                module.exit_json(host_found=False, msg="Host %s not found" % host)

        elif action == 'add_host':
            result = infoblox.create_host_record(host, network, address, comment)
            if result:
                result = infoblox.get_host_by_name(host)
                module.exit_json(changed=True, host_added=True, result=result)
            else:
                raise Exception("Option 'address' or 'network' are needed to add a new host")

        elif action == 'delete_host':
            result = infoblox.get_host_by_name(host)
            if result:
                result = infoblox.delete_host_record(host)
                module.exit_json(changed=True, hostname=host, result=result)
            else:
                raise Exception("Host %s not found" % host)

        elif action == 'set_extattr':
            result = infoblox.get_host_by_name(host)
            if result:
                host_ref = result[0]['_ref']
                result = infoblox.set_extattr(host_ref, attr_name, attr_value)
                if result:
                    module.exit_json(changed=True, result=result)
                else:
                    raise Exception()

    except Exception as e:
        module.fail_json(msg=str(e))

from ansible.module_utils.basic import *

if __name__ == "__main__":
    main()
