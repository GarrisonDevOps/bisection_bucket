| HAML templates       | `html_safe`, `raw`, `!=`      |
| Embedded Ruby (ERB)  | `html_safe`, `raw`, `<%== %>` |

In case you want to sanitize user-controlled values against XSS vulnerabilities, you can use
[`ActionView::Helpers::SanitizeHelper`](https://api.rubyonrails.org/classes/ActionView/Helpers/SanitizeHelper.html).
Calling `link_to` and `redirect_to` with user-controlled parameters can also lead to cross-site scripting.

Do also sanitize and validate URL schemes.

References:

- <i class="fa-youtube-play" aria-hidden="true"></i> [XSS Defense in Rails](https://youtu.be/2VFavqfDS6w?t=2442)
- <i class="fa-youtube-play" aria-hidden="true"></i> [XSS Defense with HAML](https://youtu.be/2VFavqfDS6w?t=2796)
- <i class="fa-youtube-play" aria-hidden="true"></i> [Validating Untrusted URLs in Ruby](https://youtu.be/2VFavqfDS6w?t=3936)
- <i class="fa-youtube-play" aria-hidden="true"></i> [RoR Model Validators](https://youtu.be/2VFavqfDS6w?t=7636)

## XML external entities

### Description

XML external entity (XXE) injection is a type of attack against an application that parses XML input. This attack occurs when XML input containing a reference to an external entity is processed by a weakly configured XML parser. It can lead to disclosure of confidential data, denial of service, server-side request forgery, port scanning from the perspective of the machine where the parser is located, and other system impacts.

### Mitigation

The two main ways we can prevent XXE vulnerabilities in our codebase are:

Use a safe XML parser: We prefer using Nokogiri when coding in Ruby. Nokogiri is a great option because it provides secure defaults that protect against XXE attacks. For more information, see the [Nokogiri documentation on parsing an HTML / XML Document](https://nokogiri.org/tutorials/parsing_an_html_xml_document.html#parse-options).

When using Nokogiri, be sure to use the default or safe parsing settings, especially when working with unsanitized user input. Do not use the following unsafe Nokogiri settings ⚠️:

| Setting | Description |
| ------ | ------ |
| `dtdload` | Tries to validate DTD validity of the object which is unsafe when working with unsanitized user input. |
| `huge` | Unsets maximum size/depth of objects that could be used for denial of service. |
| `nononet` | Allows network connections. |
| `noent` | Allows the expansion of XML entities and could result in arbitrary file reads. |

### Safe XML Library

```ruby
require 'nokogiri'

# Safe by default
doc = Nokogiri::XML(xml_string)
```

### Unsafe XML Library, file system leak

```ruby
require 'rexml/document'

# Vulnerable code
xml = <<-EOX
