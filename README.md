# ansible-infoblox
Awesome infobox module for ansible

## Dependencies

- Python "requests" module is required {pip install requests}

## Extensible Attributes

Extensible attributes are supported in this client.  It should be noted that in WAPI versions before 1.2,  the field is named "extensible_attributes", whereas in version 1.2 and later, it is named "extattrs". 

## Infoblox Version Compatibility

This gem is known to be compatible with Infoblox versions 1.0 through 2.0.  While Infoblox claims that their API is backwards-compatible, one caveat remains with the Extensible Attributes (see elsewhere in this document).  Some features are only available in newer versions (such as FixedAddress and AAAARecord).

## Usage
### Playbooke example
```

```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
