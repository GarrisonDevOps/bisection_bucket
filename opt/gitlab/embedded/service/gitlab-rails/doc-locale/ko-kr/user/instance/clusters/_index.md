---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 인스턴스 Kubernetes 클러스터(인증서 기반) (지원 중단됨)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 14.5에서 [지원 중단되었습니다](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8). 클러스터를 GitLab에 연결하려면 [GitLab Kubernetes 에이전트](../../clusters/agent/_index.md)를 사용하세요.

[프로젝트](../../project/clusters/_index.md) 및 [그룹](../../group/clusters/_index.md)을 위한 Kubernetes 클러스터와 유사하게, 인스턴스 Kubernetes 클러스터를 사용하면 Kubernetes 클러스터를 GitLab 인스턴스에 연결할 수 있으며, 여러 프로젝트에서 동일한 클러스터를 사용할 수 있습니다.

인스턴스의 Kubernetes 클러스터를 보려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **Kubernetes**를 선택합니다.

## 클러스터 우선 순위 {#cluster-precedence}

GitLab은 다음 순서로 클러스터를 매칭합니다:

- 프로젝트 클러스터
- 그룹 클러스터
- 인스턴스 클러스터

선택되려면 클러스터가 활성화되어 있어야 하며 [환경 선택기](../../../ci/environments/_index.md#limit-the-environment-scope-of-a-cicd-variable)와 일치해야 합니다.

## 클러스터 환경 {#cluster-environments}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Kubernetes 클러스터에 배포된 CI [환경](../../../ci/environments/_index.md)의 통합 보기를 보려면 [클러스터 환경](../../clusters/environments.md)에 대한 문서를 참조하세요.

## 자세한 정보 {#more-information}

GitLab과 Kubernetes를 통합하는 방법에 대한 정보는 [Kubernetes 클러스터](../../infrastructure/clusters/_index.md)를 참조하세요.
