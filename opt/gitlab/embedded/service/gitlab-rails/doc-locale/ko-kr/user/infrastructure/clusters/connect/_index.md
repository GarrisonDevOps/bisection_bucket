---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab에 클러스터 연결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[GitLab이 포함된 인증서 기반 Kubernetes 통합](../_index.md)은 GitLab 14.5에서 [지원 중단](https://gitlab.com/groups/gitlab-org/configure/-/work_items/8)되었습니다. 클러스터를 연결하려면 [GitLab Kubernetes 에이전트](../../../clusters/agent/_index.md)를 사용합니다.

## 클러스터 레벨(지원 중단) {#cluster-levels-deprecated}

> [!warning]
> [클러스터 레벨의 개념은 GitLab 14.5에서 지원 중단](../_index.md#cluster-levels)되었습니다.

클러스터의 용도에 따라 클러스터의 레벨을 선택합니다:

| 레벨                                                  | 목적 |
|--------------------------------------------------------|---------|
| [프로젝트 레벨](../../../project/clusters/_index.md)   | 단일 프로젝트에 클러스터를 사용합니다. |
| [그룹 레벨](../../../group/clusters/_index.md)       | 그룹 내의 여러 프로젝트에서 동일한 클러스터를 사용합니다. |
| [인스턴스 레벨](../../../instance/clusters/_index.md) | 인스턴스 내의 그룹 및 프로젝트 전체에서 동일한 클러스터를 사용합니다. |

### 클러스터 보기 {#view-your-clusters}

프로젝트, 그룹 또는 인스턴스에 연결된 Kubernetes 클러스터를 보려면 클러스터 레벨에 따라 클러스터의 페이지를 열립니다.

**프로젝트 레벨 클러스터**:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.

**그룹 레벨 클러스터**:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.

**인스턴스 레벨 클러스터**:

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **Kubernetes**를 선택합니다.

## 인증서로 연결된 클러스터의 보안 영향 {#security-implications-for-clusters-connected-with-certificates}

> [!warning]
> 전체 클러스터 보안은 [개발자](../../../permissions.md)를 신뢰하는 모델을 기반으로 하므로 **신뢰할 수 있는 사용자만 클러스터를 제어할 수 있도록 허용해야 합니다**.

클러스터 인증서를 사용하여 클러스터를 연결하면 컨테이너화된 애플리케이션을 성공적으로 빌드하고 배포하는 데 필요한 광범위한 기능 세트에 액세스할 수 있습니다. 클러스터에서 실행되는 모든 애플리케이션에 동일한 자격 증명이 사용된다는 점을 기억합니다.
