#!/usr/bin/python
#
#

DOCUMENTATION = '''
'''

EXAMPLES = '''

---
- hosts: localhost
  connection: local
  gather_facts: False

  vars_prompt:
    - name: ib_new_host
      prompt: "Hostname to add"
      private: no
    - name: ib_username
      prompt: "Username"
      private: no
    - name: ib_password
      prompt: "Password"
      private: yes

  tasks:
    - name: Add host
      infoblox:
        ib_server=192.168.1.1
        network=192.168.1.0/24
        action=add
        username={{ib_username}}
        password={{ib_password}}
        host={{ib_new_host}}

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
	def __init__(self, module, ib_server, username, password, api_version, dns_view, net_view):
	
		self.module = module
		self.dns_view = dns_view
		self.net_view = net_view
		self.auth = (username, password)
		self.base_url = "https://{host}/wapi/v{version}/".format(host=ib_server, version=api_version)

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

	def get_network(self, network):
		'''
		Search network in infoblox by useing rest api
		Network format supported:
			- 192.168.1.0
			- 192.168.1.0/24
		'''
		return self.invoke('get', "network", params={'network' : network, 'network_view' : self.net_view})

	def get_next_available_ip(self, network_ref):
		'''
		Return next available ip in a network range
		'''
		return self.invoke('post', network_ref, ok_codes=(200,), params={'_function' : 'next_available_ip'})

	def get_host_by_name(self, host):
		'''
		Search host by FQDN in infoblox by useing rest api
		'''
		return self.invoke('get', "record:host", params={'name': host, 'view': self.dns_view})
	
	def create_host_record(self, network, host):
		'''
		Add host in infoblox by useing rest api
		'''
		if re.match("^((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/(3[0-2]|[1-2]?[0-9])$", network):
			pass
		else:
			raise Exception(msg="Expected NET address in CIDR format")
		
		payload = {"ipv4addrs": [{"ipv4addr": "func:nextavailableip:"+network}],"name": host, "view":self.dns_view}
		return self.invoke('post', "record:host?_return_fields=ipv4addrs", ok_codes=(200, 201, 400), json=payload)
	
	def delete_host_record(self, host):
		'''
		Delete host in infoblox by useing rest api
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
			host        = dict(required=False),
			network     = dict(required=False),
			ib_server   = dict(required=False, default='192.168.0.1'),
			api_version = dict(required=False, default='1.7.1'),
			dns_view    = dict(required=False, default='Private'),
			net_view    = dict(required=False, default='default'),
			action      = dict(required=False, default='get_host', choices=['get_host', 'get_network', 'get_next_available_ip', 'add_host','delete_host']),
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
	net_view    = module.params["net_view"]
	action      = module.params["action"]
	
	try:
		infoblox = Infoblox(module, ib_server, username, password, api_version, dns_view, net_view)
		
		if action == 'get_network':
			if network:
				result = infoblox.get_network(network)
			    	if result:
			        	module.exit_json(host_found=True, result=result)
				else:
					module.exit_json(host_found=False, msg="Network %s not found" % network)
			else:
				raise Exception("Option 'address' needed to get network information")

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
			if network:
				result = infoblox.create_host_record(network, host)
		        	module.exit_json(changed=True, host_added=True, result=result)
			else:
				raise Exception("Option 'address' needed to add a host")
		elif action == 'delete_host':
			result = infoblox.get_host_by_name(host)
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
