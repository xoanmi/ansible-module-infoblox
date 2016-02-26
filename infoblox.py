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

   tasks:
   - name: Add host
     infoblox:
       ib_server=192.168.1.1
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
		return self.invoke('get', "record:host", params={'name': host, '_return_fields+' : 'comment,extattrs' ,'view': self.dns_view})
	
	def create_host_record(self, host, network, address, comment):
		'''
		Add host in infoblox by useing rest api
		'''
		if network:
			payload = {"ipv4addrs": [{"ipv4addr": "func:nextavailableip:"+network}],"name": host, "view":self.dns_view, "comment": comment}
		elif address:
			payload = {"name": host ,"ipv4addrs":[{"ipv4addr": address}],"view":self.dns_view, "comment": comment}

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

	def set_extattr(self, object_ref,  attr_name, attr_value):
		'''
		Update the extra attribute value
		'''
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
			username    = dict(required=True),
			password    = dict(required=True),
			host        = dict(required=False),
			network     = dict(required=False, default=False),
			address     = dict(required=False, default=False),
			attr_name   = dict(required=False),
			attr_value  = dict(required=False),
			comment     = dict(required=False, default="Object managed by ansible-infoblox module"),
			ib_server   = dict(required=False, default='192.168.0.1'),
			api_version = dict(required=False, default='1.7.1'),
			dns_view    = dict(required=False, default='Private'),
			net_view    = dict(required=False, default='default'),
			action      = dict(required=False, default='get_host', choices=['get_host', 'get_network', 'get_next_available_ip', 'add_host','delete_host', 'set_extattr']),
		),
		mutually_exclusive=[
			['network', 'address']
			],
		required_together=[
			['attr_name','attr_value']
			],
		supports_check_mode=True,
	)
	
	'''
	Global vars
	'''
	username    = module.params["username"]
	password    = module.params["password"]
	host        = module.params["host"]
	network     = module.params["network"]
	address     = module.params["address"]
	attr_name   = module.params["attr_name"]
	attr_value  = module.params["attr_value"]
	comment     = module.params["comment"]
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


	except Exception as err:
		module.fail_json(msg=str(err))

from ansible.module_utils.basic import *

if __name__ == "__main__":
	main()
