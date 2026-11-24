---
stage: none
group: unassigned
info: For assistance with this Style Guide page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
description: Rules for product names and standard sections in GitLab documentation.
title: Products, features, and standard sections
---

## Products and features

Refer to the information in this section when describing products and features
in the GitLab product documentation.

### Avoid line breaks in names

If a feature or product name contains spaces, don't split the name with a line break.
When names change, it is more complicated to search or grep text that has line breaks.

### Product availability details

Product availability details provide information about a feature and are displayed under the topic title.

Read more about [product availability details](availability_details.md).

## Specific sections

Certain styles should be applied to specific sections. Styles for specific
sections are outlined in this section.

### Help and feedback section

This section is displayed at the end of each document and can be omitted
by adding a key into the front matter:

```yaml
---
feedback: false
---
```

The default is to leave it there. If you want to omit it from a document, you
must check with a technical writer before doing so.

### GitLab restart

When a restart or reconfigure of GitLab is required, avoid duplication by linking
to [`doc/administration/restart_gitlab.md`](../../../administration/restart_gitlab.md)
with text like this, replacing 'reconfigure' with 'restart' as needed:

```markdown
Save the file and [reconfigure GitLab](../../../administration/restart_gitlab.md)
for the changes to take effect.
```

If the document resides outside of the `doc/` directory, use the full path
instead of the relative link:
`https://docs.gitlab.com/administration/restart_gitlab`.

### How to document different installation methods

GitLab supports five official installation methods. If you're referring to
words as part of sentences and titles, use the following phrases:

- Linux package
- Helm chart
- GitLab Operator
- Docker
- Self-compiled

It's OK to add the explanatory parentheses when
[you use tabs](#use-tabs-to-describe-a-gitlab-self-managed-configuration-procedure):

- Linux package (Omnibus)
- Helm chart (Kubernetes)
- GitLab Operator (Kubernetes)
- Docker
- Self-compiled (source)

### Use tabs to describe a GitLab Self-Managed configuration procedure

Configuration procedures can require users to edit configuration files, reconfigure
GitLab, or restart GitLab. In this case:

- Use [tabs](shortcodes.md#tabs) to differentiate among the various installation methods.
- Use the installation method names exactly as described in the previous list.
- Use them in the order described below.
- Indent the code blocks to line up with the list item they belong to.
- Use the appropriate syntax highlighting for each code block (`ruby`, `shell`, or `yaml`).
- For the YAML files, always include the parent settings.
- The final step to reconfigure or restart GitLab can be used verbatim because it's
  the same every time.

When describing a configuration edit, use this snippet, editing it as needed:

````markdown
{{</* tabs */>}}

{{</* tab title="Linux package (Omnibus)" */>}}

1. Edit `/etc/gitlab/gitlab.rb`:

   ```ruby
   external_url "https://gitlab.example.com"
   ```

1. Save the file and reconfigure GitLab:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

{{</* /tab */>}}

{{</* tab title="Helm chart (Kubernetes)" */>}}

1. Export the Helm values:

   ```shell
   helm get values gitlab > gitlab_values.yaml
   ```

1. Edit `gitlab_values.yaml`:

   ```yaml
   global:
     hosts:
       gitlab:
         name: gitlab.example.com
   ```

1. Save the file and apply the new values:

   ```shell
   helm upgrade -f gitlab_values.yaml gitlab gitlab/gitlab
   ```

{{</* /tab */>}}

{{</* tab title="Docker" */>}}

1. Edit `docker-compose.yml`:

   ```yaml
   version: "3.6"
   services:
     gitlab:
       environment:
         GITLAB_OMNIBUS_CONFIG: |
           external_url "https://gitlab.example.com"
   ```

1. Save the file and restart GitLab:

   ```shell
   docker compose up -d
   ```

{{</* /tab */>}}

{{</* tab title="Self-compiled (source)" */>}}

1. Edit `/home/git/gitlab/config/gitlab.yml`:

   ```yaml
   production: &base
     gitlab:
       host: "gitlab.example.com"
   ```

1. Save the file and restart GitLab:

   ```shell
   # For systems running systemd
   sudo systemctl restart gitlab.target

   # For systems running SysV init
   sudo service gitlab restart
   ```

{{</* /tab */>}}

{{</* /tabs */>}}
````

It renders as:

{{< tabs >}}

{{< tab title="Linux package (Omnibus)" >}}

1. Edit `/etc/gitlab/gitlab.rb`:

   ```ruby
   external_url "https://gitlab.example.com"
   ```

1. Save the file and reconfigure GitLab:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

{{< /tab >}}

{{< tab title="Helm chart (Kubernetes)" >}}

1. Export the Helm values:

   ```shell
   helm get values gitlab > gitlab_values.yaml
   ```

1. Edit `gitlab_values.yaml`:

   ```yaml
   global:
     hosts:
       gitlab:
         name: gitlab.example.com
   ```

1. Save the file and apply the new values:

   ```shell
   helm upgrade -f gitlab_values.yaml gitlab gitlab/gitlab
   ```

{{< /tab >}}

{{< tab title="Docker" >}}

1. Edit `docker-compose.yml`:

   ```yaml
   version: "3.6"
   services:
     gitlab:
       environment:
         GITLAB_OMNIBUS_CONFIG: |
           external_url "https://gitlab.example.com"
   ```

1. Save the file and restart GitLab:

   ```shell
   docker compose up -d
   ```

{{< /tab >}}

{{< tab title="Self-compiled (source)" >}}

1. Edit `/home/git/gitlab/config/gitlab.yml`:

   ```yaml
   production: &base
     gitlab:
       host: "gitlab.example.com"
   ```

1. Save the file and restart GitLab:

   ```shell
   # For systems running systemd
   sudo systemctl restart gitlab.target

   # For systems running SysV init
   sudo service gitlab restart
   ```

{{< /tab >}}

{{< /tabs >}}
