# JSON Schema Reference Resolver

## Overview

The `RefResolver` class provides HTTP/HTTPS-based resolution for external JSON schema references. It enables validation of JSON data against schemas that reference remote schema definitions, with built-in caching and timeout protection.

## Why Use RefResolver?

When working with JSON schemas, you may encounter `$ref` properties that point to external schema definitions hosted remotely:

```json
{
  "$ref": "https://example.com/schemas/common.json#/definitions/address"
}
```

The `RefResolver` solves several key challenges:

- **Remote Schema Resolution**: Automatically fetches and parses external schema definitions over HTTP/HTTPS
- **Performance Optimization**: Caches fetched schemas to avoid redundant network requests
- **Reliability**: Implements configurable timeouts to prevent hanging on slow or unresponsive endpoints
- **Error Handling**: Provides clear error messages for network failures, timeouts, and invalid JSON responses

## How to Use

### Basic Usage

The `RefResolver` is designed to work with the [JSONSchemer](https://github.com/davishmcclurg/json_schemer) gem:

```ruby
require 'labkit/json_schema/ref_resolver'

# Create a resolver instance
resolver = Labkit::JsonSchema::RefResolver.new

# Use with JSONSchemer
schema = JSONSchemer.schema(
  your_schema_hash,
  ref_resolver: resolver
)

# Validate data
schema.valid?(your_data)
```

### Custom Timeout Configuration

By default, the resolver uses a 2-second timeout for both connection and read operations. You can customize this:

```ruby
# Use a 5-second timeout
resolver = Labkit::JsonSchema::RefResolver.new(timeout_s: 5)
```

### Cache Management

The resolver maintains a class-level cache to share fetched schemas across instances:

```ruby
# Access the cache
Labkit::JsonSchema::RefResolver.cache

# Clear the cache if needed
Labkit::JsonSchema::RefResolver.cache.clear
```

## Use Case Example

The `RefResolver` is used in the User Experience SLI Registry [lib/labkit/user_experience_sli/registry.rb](../user_experience_sli/registry.rb) to validate user experience definitions against a JSON schema.

## Implementation Details

- Only HTTP and HTTPS schemes are supported. Other schemes (FTP, file://, etc.) will raise an error.
- The class-level cache is shared across all instances. In multi-threaded environments, consider using appropriate synchronization mechanisms if cache consistency is critical.
