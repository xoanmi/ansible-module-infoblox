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

This gem is known to be compatible with Infoblox versions 1.0 through 2.0.  While Infoblox claims that their API is backwards-compatible, one caveat remains with the Extensible Attributes (see elsewhere in this document).  Some features are only available in newer versions (such as FixedAddress and AAAARecord).

## Usage
### Actions
- get_network [network]
- get_next_available_ip [network] 
- get_host [hostname]
- add_host [hostname, network]
- delete_host [hostname]
- set_extattr [hostname, attirbule name, attribute value]

### Playbooke example
```
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
        action=add_host
        username={{ib_username}}
        password={{ib_password}}
        host={{ib_new_host}}
```

## To do

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
