
## Denial of Service (ReDoS) / Catastrophic Backtracking

When a regular expression (regex) is used to search for a string and can't find a match,
it may then backtrack to try other possibilities.

For example when the regex `.*!$` matches the string `hello!`, the `.*` first matches
the entire string but then the `!` from the regex is unable to match because the
character has already been used. In that case, the Ruby regex engine _backtracks_
one character to allow the `!` to match.

[ReDoS](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
is an attack in which the attacker knows or controls the regular expression used.
The attacker may be able to enter user input that triggers this backtracking behavior in a
way that increases execution time by several orders of magnitude.

### Impact

The resource, for example Puma, or Sidekiq, can be made to hang as it takes
a long time to evaluate the bad regex match. The evaluation time may require manual
termination of the resource.

### Examples

Here are some GitLab-specific examples.

User inputs used to create regular expressions:

- [User-controlled filename](https://gitlab.com/gitlab-org/gitlab/-/issues/257497)
- [User-controlled domain name](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/25314)
- [User-controlled email address](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/25122#note_289087459)

Hardcoded regular expressions with backtracking issues:

- [Repository name validation](https://gitlab.com/gitlab-org/gitlab/-/issues/220019)
- [Link validation](https://gitlab.com/gitlab-org/gitlab/-/issues/218753), and [a bypass](https://gitlab.com/gitlab-org/gitlab/-/issues/273771)
- [Entity name validation](https://gitlab.com/gitlab-org/gitlab/-/issues/289934)
- [Validating color codes](https://gitlab.com/gitlab-org/gitlab/-/commit/717824144f8181bef524592eab882dd7525a60ef)

Consider the following example application, which defines a check using a regular expression. A user entering `user@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!.com` as the email on a form will hang the web server.

```ruby
# For ruby versions < 3.2.0
# Press Control+C to terminate a hung process
class Email < ApplicationRecord
  DOMAIN_MATCH = Regexp.new('([a-zA-Z0-9]+)+\.com')

  validates :domain_matches

  private

  def domain_matches
    errors.add(:email, 'does not match') if email =~ DOMAIN_MATCH
  end
end
```

### Mitigation

#### Ruby from 3.2.0

Ruby released [Regexp improvements against ReDoS in 3.2.0](https://www.ruby-lang.org/en/news/2022/12/25/ruby-3-2-0-released/). ReDoS will no longer be an issue, with the exception of _"some kind of regular expressions, such as those including advanced features (like back-references or look-around), or with a huge fixed number of repetitions"_.
