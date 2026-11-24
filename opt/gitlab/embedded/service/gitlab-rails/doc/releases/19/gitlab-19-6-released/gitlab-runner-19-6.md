---
title: GitLab Runner 19.6
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.6&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

We're also releasing GitLab Runner 19.6 today! GitLab Runner is the highly-scalable build agent that runs your CI/CD jobs and sends the results back to a GitLab instance. GitLab Runner works in conjunction with GitLab CI/CD, the open-source continuous integration service included with GitLab.

**What's New**

- [On GitLab.com, the Job Router now uses an internal relay address and records where the correlation ID comes from.](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39944)
- [GitLab Runner now provides a `direct_download` setting in `[runners.artifact]` that replaces the deprecated `FF_USE_DIRECT_DOWNLOAD` feature flag](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39682)
- [GitLab Runner now provides a native package for Ubuntu 26.04 (Resolute)](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39449)
- [GitLab Runner can now use HTTP/2 for GitLab API requests. HTTP/2 is off by default. To turn it on, set `allow_http2` to `true`.](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/28862)
- [Kubernetes executor pause pods now support labels and annotations](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39844), and [use the same node affinity and scheduler as job pods, with an experimental `preemptive_mode` that requests jobs only when capacity is available](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39615)
- [The Kubernetes executor job log now shows the helper image in use](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/2387)
- [Toggle collapsing build sections in job log](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/38932)

**Bug Fixes**

- [Community fork pipelines fail with `gitlab_secrets_manager source group with path 'gitlab-org' not found`](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/40099)
- [Behavior of register flag `--docker-pull-policy` changed and is inconsistent with other flags](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/40013)
- [`FF_CONCRETE` jobs now use the configured shell. Jobs with `shell = "sh"` that use bash-only syntax, such as arrays or `[[ ]]`, might now fail.](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39955)
- [Docker autoscaler prunes active instances mid-job on v19.3.1, independent of token rotation](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39811)
- [Distinguish runner-controlled source-fetch failures from user script failures](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39695)
- [`FF_USE_GIT_NATIVE_CLONE` clones the mutable merge request merge ref instead of the pipeline SHA, breaking merged results pipelines when the target branch advances](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39641)
- [Docker executor with Podman runtime: seccomp profile path rewritten to inline JSON, causing `file name too long` error in GitLab Runner 19.x](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39496)
- [Docker autoscaler fails jobs because it can't remove networks on terminated instances when `FF_NETWORK_PER_BUILD` is enabled](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39145)
- [Jobs that use an unmasked `/proc` mount no longer fail with the Kubernetes executor. The runner now turns on user namespaces for these jobs, which Kubernetes requires for an unmasked mount.](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39399)
- [Graceful shutdown (`SIGQUIT`) cancels in-flight jobs and job requests, orphaning jobs that GitLab already assigned](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39847)
- [With `FF_USE_PARALLEL_CACHE_TRANSFER` or `FF_USE_PARALLEL_ARTIFACT_TRANSFER` enabled, cache and artifact downloads silently corrupt files when a server or proxy ignores `Range` requests](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/40102)
- [GitLab Runner fails when a nested submodule is removed and `GIT_STRATEGY` is `fetch`](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/38871)
- [Kubernetes executor image pull retry fails the job with `pod is being deleted`](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39817)
- [With `FF_KUBERNETES_HONOR_ENTRYPOINT=true`, the Kubernetes executor ignores service commands](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/40237) and [duplicates job logs on nodes with a non-UTC time zone](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39470)
- [Setting a feature flag in a pipeline results in a duplicate environment variable on the Kubernetes pod](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/36893)
- [Docker executor `id -u` check for runners without `umask` breaks when the image sets an `ENTRYPOINT`](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/40014)

The list of all changes is in the GitLab Runner [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-6-stable/CHANGELOG.md).
