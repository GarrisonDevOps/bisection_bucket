=> "my-safe-site.com-my-evil-site.com"

# Here's an example where we unsafely attempt to validate a host while allowing for
# subdomains
user_supplied_url = "https://my-evil-site-my-safe-site.com"
user_supplied_host = URI.parse(user_supplied_url).host
=> "my-evil-site-my-safe-site.com"
user_supplied_host.end_with?("my-safe-site.com")      # Don't trust with end_with?
=> true
```

## XSS guidelines

### Description

Cross site scripting (XSS) is an issue where malicious JavaScript code gets injected into a trusted web application and executed in a client's browser. The input is intended to be data, but instead gets treated as code by the browser.

XSS issues are commonly classified in three categories, by their delivery method:

- [Persistent XSS](https://owasp.org/www-community/Types_of_Cross-Site_Scripting#stored-xss-aka-persistent-or-type-i)
- [Reflected XSS](https://owasp.org/www-community/Types_of_Cross-Site_Scripting#reflected-xss-aka-non-persistent-or-type-ii)
- [DOM XSS](https://owasp.org/www-community/Types_of_Cross-Site_Scripting#dom-based-xss-aka-type-0)

### Impact

The injected client-side code is executed on the victim's browser in the context of their current session. This means the attacker could perform the same actions the victim would typically be able to do through a browser. The attacker would also have the ability to:

- <i class="fa-youtube-play" aria-hidden="true"></i> [log victim keystrokes](https://youtu.be/2VFavqfDS6w?t=1367)
- launch a network scan from the victim's browser
- potentially <i class="fa-youtube-play" aria-hidden="true"></i> [obtain the victim's session tokens](https://youtu.be/2VFavqfDS6w?t=739)
- perform actions that lead to data loss/theft or account takeover

Much of the impact is contingent upon the function of the application and the capabilities of the victim's session. For further impact possibilities, check out [the beef project](https://beefproject.com/).

For a demonstration of the impact on GitLab with a realistic attack scenario, see [this video on the GitLab Unfiltered channel](https://www.youtube.com/watch?v=t4PzHNycoKo) (internal, it requires being logged in with the GitLab Unfiltered account).

### Mitigation and prevention in Rails

By default, Rails automatically escapes strings when they are inserted into HTML templates. Avoid the
methods used to keep Rails from escaping strings, especially those related to user-controlled values.
Specifically, the following options are dangerous because they mark strings as trusted and safe:

| Method               | Avoid these options           |
|----------------------|-------------------------------|
