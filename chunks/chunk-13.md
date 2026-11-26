code is secure when it merges, it's better practice to use the defense-in-depth
"single recipient" check just before sending the email. This prevents a vulnerability
if otherwise-vulnerable code is committed at a later date. For example:

### Example

```ruby
# Insecure if email is user-controlled
def insecure_email(email)
  mail(to: email, subject: 'Password reset email')
end

# A single recipient, just as a developer expects
insecure_email("person@example.com")

# Multiple emails sent when an array is passed
insecure_email(["person@example.com", "attacker@evil.com"])

# Multiple emails sent even when a single string is passed
insecure_email("person@example.com, attacker@evil.com")
```

### Prevention and defense

- Use `Gitlab::Email::SingleRecipientValidator` when adding new emails intended for a single recipient
- Strongly type your code by calling `.to_s` on values, or check its class with `value.kind_of?(String)`

## Request Parameter Typing

This Secure Code Guideline is enforced by the `StrongParams` RuboCop.

In our Rails Controllers you must use `ActionController::StrongParameters`. This ensures that we explicitly define the keys and types of input we expect in a request. It is critical for avoiding Mass Assignment in our Models. It should also be used when parameters are passed to other areas of the GitLab codebase such as Services.

Using `params[:key]` can lead to vulnerabilities when one part of the codebase expects a type like `String`, but gets passed (and handles unsafely and without error) an `Array`.

> [!note]
> This only applies to Rails Controllers. Our API and GraphQL endpoints enforce strong typing, and Go is statically typed.

### Example

```ruby
class MyMailer
  def reset(user, email)
    mail(to: email, subject: 'Password reset email', body: user.reset_token)
  end
end

class MyController

  # Bad - email could be an array of values
  # ?user[email]=VALUE will find a single user and email a single user
  # ?user[email][]=victim@example.com&user[email][]=attacker@example.com will email the victim's token to the victim and user
  def dangerously_reset_password
    user = User.find_by(email: params[:user][:email])
    MyMailer.reset(user, params[:user][:email])
  end

  # Good - we use StrongParams which doesn't permit the Array type
  # ?user[email]=VALUE will find a single user and email a single user
  # ?user[email][]=victim@example.com&user[email][]=attacker@example.com will fail because there is no permitted :email key
  def safely_reset_password
    user = User.find_by(email: email_params[:email])
    MyMailer.reset(user, email_params[:email])
