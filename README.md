# ansible-infoblox
Awesome infobox module for ansible

## Dependencies

- Python "requests" module is required
```
sudo pip install requests
```

## Extensible Attributes

Extensible attributes are supported in this client.  It should be noted that in WAPI versions before 1.2,  the field is named "extensible_attributes", whereas in version 1.2 and later, it is named "extattrs". 

## Infoblox Version Compatibility

This gem is known to be compatible with Infoblox versions 1.0 through 2.3.  While Infoblox claims that their API is backwards-compatible, one caveat remains with the Extensible Attributes (see elsewhere in this document).  Some features are only available in newer versions (such as FixedAddress and AAAARecord).

## Usage
### Actions
- get_network [network]
- get_next_available_ip [network] 
- get_host [hostname]
- add_host [hostname, network]
- delete_host [hostname]
- set_extattr [hostname, attirbule name, attribute value]
- get_a_record [name]
- set_a_record [name, address] (this will change an existing record if it exists)
- delete_a_record [name]

### Playbooke example
```
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
     debug: msg="Get crazy!!"
```
## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
