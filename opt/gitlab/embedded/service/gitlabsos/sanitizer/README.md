# gitlabrb_sanitizer

Sanitizes the `gitlab.rb` file by redacting and replacing sensitive config variables.
The sanitizer prints the result to stdout, no changes are made to the `gitlab.rb` file itself.

## Usage

```shell
cd /tmp
/opt/gitlab/embedded/bin/git clone --depth=1 https://gitlab.com/gitlab-com/support/toolbox/gitlabrb_sanitizer.git
cd gitlabrb_sanitizer
less sanitizer.rb # Please review before executing
/opt/gitlab/embedded/bin/ruby sanitizer.rb # --file /etc/gitlab/gitlab.rb is the default
```

Please find more options via `/opt/gitlab/embedded/bin/ruby sanitizer.rb --help`:

```shell
Usage: sanitizer.rb [options]

Specific options:
    -f, --file FILE                  Sanitize FILE (default: /etc/gitlab/gitlab.rb)
    -s, --save FILE                  Save output to FILE (default: outputs to stdout)
    -d, --sanitize-domains           Sanitize domains
    -i, --sanitize-ips               Sanitize IP addresses
    -e, --sanitize-emails            Sanitize email addresses
    -h, --help                       Show this usage message and quit.
```

### Execute Directly

**Please review script before executing anything directly into sudo!**

```sh
curl -s https://gitlab.com/gitlab-com/support/toolbox/gitlabrb_sanitizer/-/raw/main/sanitizer.rb | sudo /opt/gitlab/embedded/bin/ruby
```

## Alternatives

See [our "How do I scrub sensitive information?" documentation](https://about.gitlab.com/support/sensitive-information/#how-do-i-scrub-sensitive-information).

## Contributing

Feel free to open an issue or merge request.

### Testing locally

You can execute the `test_sanitizer` shell script. The script grabs the latest GitLab Omnibus configuration template, runs it through the sanitizer (with `--sanitize-domains`) and shows the output. Make sure your changes don't cause anything to show up in the output that was beind sanitized before.

```
$> ./test_sanitizer
Notification secret, it's used to authenticate notification requests to GitLab application
  'KEYS': ''
mattermost['gitlab_id'] = "12345656"
!  The only acceptably unredacted output here should be: 'KEYS': '…'
!  from the redis['rename_commands'] block, which aren't secret.
!
!  Any other output means:
!    - either our sanitizer overlooked some key or secret => MR here ;-)
!    - or a placeholder in .rb.template has a new pattern => MR there:
!      https://gitlab.com/gitlab-org/omnibus-gitlab/-/edit/master/files/gitlab-config-template/gitlab.rb.template
!    - or an explanation isn't prepended with multiple ## => MR there:
```

### Updating GitLabSOS project

The sanitizer is being used in the [gitlabsos](https://gitlab.com/gitlab-com/support/toolbox/gitlabsos) project as a submodule. The submodule there should be updated to incorporate the latest sanitizer version regularly. To do so:

1. Checkout the [gitlabsos](https://gitlab.com/gitlab-com/support/toolbox/gitlabsos) repository locally
1. `cd gitlabsos`
1. `git checkout -b 'update-sanitizer'`
1. `git submodule init`
1. `git submodule update`
1. `cd sanitizer`
1. `git pull origin main`
1. `cd ..`
1. `git add sanitizer`
1. `git commit -m 'Update sanitizer module'`
1. Push the branch and open a merge request in the [gitlabsos](https://gitlab.com/gitlab-com/support/toolbox/gitlabsos) project
