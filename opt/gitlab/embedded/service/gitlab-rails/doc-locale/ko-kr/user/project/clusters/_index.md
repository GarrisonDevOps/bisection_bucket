---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 프로젝트 수준 Kubernetes 클러스터(인증서 기반)(사용 중단)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.5에서 [더 이상 사용되지 않습니다](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8). 클러스터를 GitLab에 연결하려면 [Kubernetes용 GitLab 에이전트](../../clusters/agent/_index.md)를 사용하세요.

[프로젝트 수준](../../infrastructure/clusters/connect/_index.md#cluster-levels-deprecated) Kubernetes 클러스터를 사용하면 Kubernetes 클러스터를 GitLab의 프로젝트에 연결할 수 있습니다.

[여러 클러스터를 연결](multiple_kubernetes_clusters.md)하여 단일 프로젝트에 추가할 수도 있습니다.

## 프로젝트 수준 클러스터 보기 {#view-your-project-level-clusters}

프로젝트 수준 Kubernetes 클러스터를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택하세요.
