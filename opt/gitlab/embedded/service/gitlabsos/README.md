# gitlabsos

gitlabsos provides a unified method of gathering info and logs from GitLab
and the system it's running on.

# Automatically installed with GitLab Linux Packages

Since GitLab version 18.3 `gitlabsos` is part of the [Linux package](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/8565).
You can now run:

```sh
sudo gitlabsos
```

With earlier versions follow the usage instructions below. 

# Using Kubernetes or scaled architecture?

Consider [KubeSOS](https://gitlab.com/gitlab-com/support/toolbox/kubesos) or our [Ansible playbook](https://gitlab.com/gitlab-com/support/toolbox/ansible-playbook-gitlabsos)

## When you should run the script

If performance is degraded, then the script works best if you run it _while_
you're experiencing the issue.

If you're reproducing a software error (like a 500 error), then the script works
best if you run it just _after_ the issue.

Don't fret if you miss your window of opportunity.
Estimate useful values for the `--max-file-size` and/or `--after-date` parameters
via the timestamp of relevant events and/or by whether they're included in the `.tar.gz` file
and rerun the script as necessary.
Regardless, any run will gather a wealth of helpful information for
identifying issues.

See below for examples

- Collect `N` days worth of logs using the `--days` argument.
  These will create much larger SOS archives!
  Ensure that your server has sufficient free space, including the `/tmp` mount. Alternatively you can adjust the [temporary location for holding logs for collection](https://gitlab.com/gitlab-com/support/toolbox/gitlabsos#set-temporary-file-location) and [the destination folder](https://gitlab.com/gitlab-com/support/toolbox/gitlabsos#usage) with `--output-file FILE` to circumvent size limitations quickly.

```sh
# Collect today's logs only
sudo /opt/gitlab/embedded/bin/ruby ./gitlabsos.rb --days 1
sudo /opt/gitlab/embedded/bin/ruby ./gitlabsos.rb --days today

# Collect last week's logs
sudo /opt/gitlab/embedded/bin/ruby ./gitlabsos.rb --days 7

# Collect last 30 days of logs
sudo /opt/gitlab/embedded/bin/ruby ./gitlabsos.rb --days 30
```

- (**Advanced**) Collect logs from a specific day:

```sh
# Capture logs that were **last written** to on September 5th, which would be the logs for September 4th.
sudo /opt/gitlab/embedded/bin/ruby ./gitlabsos.rb --after-date 2024-09-05 --before-date 2024-09-06
```

## Limitations

- **Works on Omnibus installs and GitLab Docker images**. This means that the script won't collect
    GitLab-related information for k8s chart deployments or source installs.
    Use [our kubesos script](https://gitlab.com/gitlab-com/support/toolbox/kubesos#kubesos) instead (for k8s).
- The resulting archive _could_ end up being large. In an attempt to reduce the
    log and archive size, gitlabsos only grabs the last 30MB of each latest log file version.
    `logrotate`d files -- which are included when using the `--after-date`,
    `--before-date` and/or `--days` parameters -- will be included without truncation.
    In case you want to provide files to GitLab Support that are larger than our ticket system's attachment limit,
    [use our workaround options](https://about.gitlab.com/support/providing-large-files/).

## Dependencies

The script doesn't really have any depedencies other than an Omnibus install of
GitLab. The script will attempt to execute a list of commands (listed in 
`list_commands`). But these programs are all optional and only "nice to have". 
If the info that was gathered is lacking something important, then we may
suggest installing something, but that would be a rare situation.

## Get started

### Usage

If needed, you can always double-check the available options by running `./gitlabsos.rb --help`.

```text
Usage: gitlabsos.rb [options]
    -o, --output-file FILE           Write gitlabsos report to FILE
        --tmp-path PATH              Specify directory to write temporary files to
        --after-date DATE            Get logs from after a certain date
        --before-date DATE           Get logs from before a certain date
        --days DAYS                  Get logs from the last N days
        --debug                      Set the log level to debug
        --skip-root-check            Run the script as non-root. Warning: script might fail
        --skip-config                Don't include a sanitized copy of the gitlab.rb configuration file.
        --include-rpm-vv             Run 'rpm -vV' which can result in a large output file (>12MB)
        --include-stats              Include using fast-stats to collect log statistics.
        --skip-schema                Don't run the slow Postgres schema dump
        --skip-rake                  Don't run the slow Rake commands
        --max-file-size MB           Set the max file size (in megabytes) for any file in the report
    -h, --help                       Prints this help
        --nice niceness              Set CPU priority for archive creation
```

### Run the script

The gitlabsos program is a simple ruby script, and is designed to run "out of
the box" without any further configuration. See below for an example of how
you can execute the script.

```sh
/opt/gitlab/embedded/bin/git clone --recursive https://gitlab.com/gitlab-com/support/toolbox/gitlabsos.git && cd gitlabsos
sudo /opt/gitlab/embedded/bin/ruby ./gitlabsos.rb
```

If your GitLab consists of [multiple nodes](https://docs.gitlab.com/ee/administration/reference_architectures/#gitlab-package-omnibus),
running gitlabsos on all nodes is recommended.

#### Execute directly

Running gitlabsos with this method **will not** collect the `gitlab.rb` file.

```sh
curl https://gitlab.com/gitlab-com/support/toolbox/gitlabsos/raw/main/gitlabsos.rb | sudo /opt/gitlab/embedded/bin/ruby
```

#### Execute on a network not connected to the internet

If your GitLab server is blocked from the outside internet, you can copy the contents
of [this file](./gitlabsos.rb) into a file named `gitlabsos.rb` on your GitLab
server and run it with the following:

```sh
sudo /opt/gitlab/embedded/bin/ruby gitlabsos.rb
```

#### Run gitlabsos in a GitLab Docker Container

First capture the gitlabsos report by executing the `gitlabsos` script in your GitLab container

```sh
sudo docker exec -it <gitlab-container-name> bash -c "curl https://gitlab.com/gitlab-com/support/toolbox/gitlabsos/raw/main/gitlabsos.rb | /opt/gitlab/embedded/bin/ruby"
```

Then copy the gitlabsos report outside the Docker Container to attach it to your Support ticket

```sh
sudo docker cp <gitlab-container-name>:gitlabsos.example.com_<timestamp>.tar.gz .
```

#### Set temporary file location

GitLabSOS copies logs to a temporary location before compressing the files. The temporary file location is based on the first value set in the following order:

1. `--tmp-path` option
1. `TMP` environment variable
1. `TMPDIR` environment variable 
1. `/tmp` (default)

NOTE:
A specified path will be created if it does not already exist. The logs will be compressed and stored in the output file once complete, 
but any newly created directories will not be deleted.

For example: 

```sh
/opt/gitlab/embedded/bin/git clone --recursive https://gitlab.com/gitlab-com/support/toolbox/gitlabsos.git && cd gitlabsos
sudo /opt/gitlab/embedded/bin/ruby ./gitlabsos.rb --tmp-path /new/tmp/path
```

### Output

The script will log some output to your terminal that should look something like this:

```text
gitlabhost:/home/user1/gitlabsos# sudo ./gitlabsos.rb
[2019-08-08T19:43:19.552020] INFO -- gitlabsos: Starting gitlabsos report
[2019-08-08T19:43:19.552141] INFO -- gitlabsos: Gathering configuration and system info..
[2019-08-08T19:43:19.554574] INFO -- gitlabsos: Collecting diagnostics. This will probably take a few minutes..
[2019-08-08T19:43:19.585381] WARN -- gitlabsos: command 'getenforce' doesn't exist
[2019-08-08T19:43:19.588019] WARN -- gitlabsos: command 'sestatus' doesn't exist
[2019-08-08T19:44:12.906677] WARN -- gitlabsos: command 'iotop -aoPqt -b -d 1 -n 10' doesn't exist
[2019-08-08T19:44:33.692803] INFO -- gitlabsos: Getting GitLab logs..
[2019-08-08T19:44:33.790908] INFO -- gitlabsos: Getting unicorn worker active/queued stats..
[2019-08-08T19:44:48.811356] INFO -- gitlabsos: Report finished.
/home/user1/gitlabsos/gitlabsos.user1-gitlabomnibus_20190808194319.tar.gz
```

You'll see several INFO and WARN level log entries. As long as you see "Report
finished" at the end, followed by the path to the tar archive, then you can
safely ignore the rest of the output.

## Analyzing the collected data

Use the [GitLab Diagnostics GUI](https://gitlab.com/gitlab-com/support/toolbox/gitlab-diagnostics-gui) to interactively explore and analyze your GitLabSOS tarball data.

# I want to add something to gitlabsos

You can! Also consider if relevant to add it to [KubeSOS](https://gitlab.com/gitlab-com/support/toolbox/kubesos)

# What's the relationship between GitLabSOS and KubeSOS?

Both are used to make debugging easier, and attempt to get relevant information from environments. They are not dependencies of each other, just sibling projects!
