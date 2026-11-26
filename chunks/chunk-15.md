
This class can be refactored to use the `Forwardable` method and `def_delegators`:

```ruby
class User
  extend Forwardable

  def initialize(attributes)
    @options = OpenStruct.new(attributes)

    self.class.instance_eval do
      def_delegators :@options, *attributes.keys
    end
  end

  def is_admin?
    name.eql?("Sid") # Note - never do this!
  end
end
```

It might seem like this example has the same behavior as the first code example. However, there's one crucial difference: because the delegators are meta-programmed after the class is loaded, it can overwrite existing methods:

```ruby
User.new({name: "Jeeves"}).is_admin?
# => false

User.new(name: "Sid").is_admin?
# => true

User.new(name: "Jeeves", "is_admin?" => true).is_admin?
# => true
#     ^------------------ The method is overwritten! Sneaky Jeeves!
```

In the example above, the `is_admin?` method is overwritten when passing it to the initializer.

### Best practices

- Never pass user-provided details into method-defining metaprogramming methods.
  - If you must, be very confident that you've sanitized the values correctly.
    Consider creating an allowlist of values, and validating the user input against that.
- When extending classes that use metaprogramming, make sure you don't inadvertently override any method definition safety checks.

## Serialization

Serialization of active record models can leak sensitive attributes if they are not protected.

Using the [`prevent_from_serialization`](https://gitlab.com/gitlab-org/gitlab/-/blob/d7b85128c56cc3e669f72527d9f9acc36a1da95c/app/models/concerns/sensitive_serializable_hash.rb#L11)
method protects the attributes when the object is serialized with `serializable_hash`.
When an attribute is protected with `prevent_from_serialization`, it is not included with
`serializable_hash`, `to_json`, or `as_json`.

For more guidance on serialization:

- [Why using a serializer is important](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/serializers/README.md#why-using-a-serializer-is-important).
- Always use [Grape entities](../api_styleguide.md#entities) for the API.

To `serialize` an `ActiveRecord` column:

- You can use `app/serializers`.
- You cannot use `to_json / as_json`.
- You cannot use `serialize :some_colum`.

### Serialization example

The following is an example used for the [`TokenAuthenticatable`](https://gitlab.com/gitlab-org/gitlab/-/blob/9b15c6621588fce7a80e0438a39eeea2500fa8cd/app/models/concerns/token_authenticatable.rb#L30) class:

```ruby
prevent_from_serialization(*strategy.token_fields) if respond_to?(:prevent_from_serialization)
```
