---
stage: none
group: unassigned
info: Any user with at least the Maintainer role can merge updates to this content. For details, see <https://docs.gitlab.com/development/development_processes/#development-guidelines-review>.
title: Secure coding development guidelines
---

This document contains descriptions and guidelines for secure Ruby programming practices commonly needed in the GitLab codebase. These guidelines are intended to help developers write secure Ruby code from the start, identify potential security vulnerabilities early in the development process, and follow Ruby-specific best practices. By adhering to these standards, we aim to reduce the number of security vulnerabilities released over time while leveraging Ruby's built-in security features effectively.

## Regular Expressions guidelines

### Anchors / Multi line in Ruby

Unlike other programming languages (for example, Perl or Python) Regular Expressions are matching multi-line by default in Ruby. Consider the following example in Python:

```python
import re
text = "foo\nbar"
matches = re.findall("^bar$",text)
print(matches)
```

The Python example will output an empty array (`[]`) as the matcher considers the whole string `foo\nbar` including the newline (`\n`). In contrast Ruby's Regular Expression engine acts differently:

```ruby
text = "foo\nbar"
p text.match /^bar$/
```

The output of this example is `#<MatchData "bar">`, as Ruby treats the input `text` line by line. To match the whole string, the Regex anchors `\A` and `\z` should be used.

#### Impact

This Ruby Regex specialty can have security impact, as often regular expressions are used for validations or to impose restrictions on user-input.

#### Examples

GitLab-specific examples can be found in the following [path traversal](https://gitlab.com/gitlab-org/gitlab/-/issues/36029#note_251262187)
and [open redirect](https://gitlab.com/gitlab-org/gitlab/-/issues/33569) issues.

Another example would be this fictional Ruby on Rails controller:

```ruby
class PingController < ApplicationController
  def ping
    if params[:ip] =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/
      render :text => `ping -c 4 #{params[:ip]}`
    else
      render :text => "Invalid IP"
    end
  end
end
```

Here `params[:ip]` should not contain anything else but numbers and dots. However this restriction can be bypassed as the Regex anchors `^` and `$` are being used. Ultimately this leads to a shell command injection in `ping -c 4 #{params[:ip]}` by using newlines in `params[:ip]`.

#### Mitigation

In most cases the anchors `\A` for beginning of text and `\z` for end of text should be used instead of `^` and `$`.
