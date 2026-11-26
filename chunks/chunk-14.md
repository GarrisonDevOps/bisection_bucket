  end

  # This returns a new ActionController::Parameters that includes only the permitted attributes
  def email_params
    params.require(:user).permit(:email)
  end
end
```

This class of issue applies to more than just email; other examples might include:

- Allowing multiple One Time Password attempts in a single request: `?otp_attempt[]=000000&otp_attempt[]=000001&otp_attempt[]=000002...`
- Passing unexpected parameters like `is_admin` that are later `.merged` in a Service class

### Related topics

- [Watch a walkthrough video](https://www.youtube.com/watch?v=ydg95R2QKwM) for an instance of this issue causing vulnerability CVE-2023-7028.
  The video covers what happened, how it worked, and what you need to know for the future.
- Rails documentation for [ActionController::StrongParameters](https://api.rubyonrails.org/classes/ActionController/StrongParameters.html) and [ActionController::Parameters](https://api.rubyonrails.org/classes/ActionController/Parameters.html)

## Guidelines when defining missing methods with metaprogramming

Metaprogramming is a way to define methods at runtime, instead of at the time of writing and deploying the code. It is a powerful tool, but can be dangerous if we allow untrusted actors (like users) to define their own arbitrary methods. For example, imagine we accidentally let an attacker overwrite an access control method to always return true! It can lead to many classes of vulnerabilities such as access control bypass, information disclosure, arbitrary file reads, and remote code execution.

Key methods to watch out for are `method_missing`, `define_method`, `delegate`, and similar methods.

### Insecure metaprogramming example

This example is adapted from an example submitted by [@jobert](https://hackerone.com/jobert?type=user) through our HackerOne bug bounty program.
Thank you for your contribution!

Before Ruby 2.5.1, you could implement delegators using the `delegate` or `method_missing` methods. For example:

```ruby
class User
  def initialize(attributes)
    @options = OpenStruct.new(attributes)
  end

  def is_admin?
    name.eql?("Sid") # Note - never do this!
  end

  def method_missing(method, *args)
    @options.send(method, *args)
  end
end
```

When a method was called on a `User` instance that didn't exist, it passed it along to the `@options` instance variable.

```ruby
User.new({name: "Jeeves"}).is_admin?
# => false

User.new(name: "Sid").is_admin?
# => true

User.new(name: "Jeeves", "is_admin?" => true).is_admin?
# => false
```

Because the `is_admin?` method is already defined on the class, its behavior is not overridden when passing `is_admin?` to the initializer.
