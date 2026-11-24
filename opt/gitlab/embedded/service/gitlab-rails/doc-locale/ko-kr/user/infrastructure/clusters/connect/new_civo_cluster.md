---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Civo Kubernetes 클러스터 생성
---

모든 새 Civo 계정은 Civo Kubernetes를 통한 GitLab 통합을 시작하기 위해 [$250 크레딧](https://dashboard.civo.com/signup)을 받습니다. 마켓플레이스 앱을 사용하여 Civo Kubernetes 클러스터에 GitLab을 설치할 수도 있습니다.

[코드 기반 인프라(IaC)](../../_index.md)를 통해 Civo Kubernetes에서 새 클러스터를 생성하는 방법을 알아봅니다. 이 프로세스에서는 Civo 및 Kubernetes Terraform 공급자를 사용하여 Civo Kubernetes 클러스터를 생성합니다. Kubernetes용 GitLab 에이전트를 사용하여 클러스터를 GitLab에 연결합니다.

**시작하기 전에**:

- [Civo 계정](https://dashboard.civo.com/signup).
- [러너](https://docs.gitlab.com/runner/install/) GitLab CI/CD 파이프라인을 실행할 수 있습니다.

**단계**:

1. [예제 프로젝트 가져오기](#import-the-example-project).
1. [Kubernetes용 에이전트 등록](#register-the-agent).
1. [프로젝트 구성](#configure-your-project).
1. [클러스터 프로비저닝](#provision-your-cluster).

## 예제 프로젝트 가져오기 {#import-the-example-project}

GitLab에서 코드 기반 인프라를 사용하여 클러스터를 생성하려면 클러스터를 관리할 프로젝트를 생성해야 합니다. 이 자습서에서는 샘플 프로젝트로 시작한 다음 필요에 따라 수정합니다.

[URL로 예제 프로젝트 가져오기](../../../import/third_party_systems/repo_by_url.md)를 시작합니다.

프로젝트를 가져오려면:

1. GitLab의 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. **내 모든 프로젝트 보기**를 선택합니다.
1. 페이지 오른쪽에서 **새 프로젝트**를 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.
1. **리포지토리 URL**을 선택합니다.
1. **Git 리포지토리 URL**의 경우 `https://gitlab.com/civocloud/gitlab-terraform-civo.git`을 입력합니다.
1. 필드를 완료하고 **프로젝트 생성**을 선택합니다.

이 프로젝트는 다음을 제공합니다:

- 이름, 지역, 노드 수 및 Kubernetes 버전의 기본값이 있는 [Civo의 클러스터](https://gitlab.com/civocloud/gitlab-terraform-civo/-/blob/master/civo.tf).
- 클러스터에 설치된 [Kubernetes용 GitLab 에이전트](https://gitlab.com/civocloud/gitlab-terraform-civo/-/blob/master/agent.tf).

## 에이전트 등록 {#register-the-agent}

Kubernetes용 GitLab 에이전트를 생성하려면:

1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. **클러스터 연결**을 선택합니다.
1. **에이전트 선택** 드롭다운 목록에서 `civo-agent`을 선택한 다음 **등록**을 선택합니다.
1. GitLab은 에이전트에 대한 에이전트 액세스 토큰을 생성합니다. 나중에 필요하므로 이 비밀 토큰을 안전하게 저장합니다.
1. GitLab은 에이전트 서버(KAS)에 대한 주소를 제공하며, 나중에 필요할 것입니다.

## 프로젝트 구성 {#configure-your-project}

CI/CD 환경 변수를 사용하여 프로젝트를 구성합니다.

**필수 구성**:

1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **변수**를 펼칩니다.
1. 변수 `CIVO_TOKEN`을(를) Civo 계정의 토큰으로 설정합니다.
1. 변수 `TF_VAR_agent_token`을(를) 이전 작업에서 받은 에이전트 토큰으로 설정합니다.
1. 변수 `TF_VAR_kas_address`을(를) 이전 작업의 에이전트 서버 주소로 설정합니다.

![필수 구성](img/variables_civo_v17_3.png)

**선택 사항 구성**:

[`variables.tf`](https://gitlab.com/civocloud/gitlab-terraform-civo/-/blob/master/variables.tf) 파일은 필요에 따라 재정의할 수 있는 다른 변수를 포함합니다:

- `TF_VAR_civo_region`: 클러스터의 지역을 설정합니다.
- `TF_VAR_cluster_name`: 클러스터의 이름을 설정합니다.
- `TF_VAR_cluster_description`: 클러스터에 대한 설명을 설정합니다. Civo 클러스터 세부 페이지에서 GitLab 프로젝트에 대한 참조를 생성하려면 이 값을 `$CI_PROJECT_URL`으로 설정합니다. 이 값은 Civo 대시보드에서 본 클러스터 프로비저닝을 담당한 프로젝트를 결정하는 데 도움이 됩니다.
- `TF_VAR_target_nodes_size`: 클러스터에 사용할 노드의 크기를 설정합니다.
- `TF_VAR_num_target_nodes`: Kubernetes 노드의 수를 설정합니다.
- `TF_VAR_agent_version`: Kubernetes용 GitLab 에이전트의 버전을 설정합니다.
- `TF_VAR_agent_namespace`: Kubernetes용 GitLab 에이전트의 Kubernetes 네임스페이스를 설정합니다.

[Civo Terraform 공급자](https://registry.terraform.io/providers/civo/civo/latest/docs/resources/kubernetes_cluster) 및 [Kubernetes Terraform 공급자](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs) 설명서를 참조하여 추가 리소스 옵션을 확인합니다.

## 클러스터 프로비저닝 {#provision-your-cluster}

프로젝트를 구성한 후 클러스터의 프로비저닝을 수동으로 트리거합니다. GitLab에서:

1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. **새 파이프라인**을 선택합니다.
1. **파이프라인 실행**을 선택한 다음 목록에서 새로 생성된 파이프라인을 선택합니다.
1. **배포** 작업 옆에서 **수동 작업** ({{< icon name="status_manual" >}})을 선택합니다.

파이프라인이 성공적으로 완료되면 새 클러스터를 볼 수 있습니다:

- Civo 대시보드: Kubernetes 탭에서.
- GitLab: 프로젝트의 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.

`TF_VAR_civo_region` 변수를 설정하지 않으면 클러스터가 'lon1' 지역에 생성됩니다.

## 클러스터 사용 {#use-your-cluster}

클러스터를 프로비저닝한 후에는 GitLab에 연결되어 있고 배포할 준비가 되었습니다. 연결을 확인하려면:

1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. 목록에서 **연결 상태** 열을 확인합니다.

연결 기능에 대한 자세한 내용은 [Kubernetes용 GitLab 에이전트 설명서](../_index.md)를 참조하세요.

## 클러스터 제거 {#remove-the-cluster}

정리 작업이 기본적으로 파이프라인에 포함됩니다.

생성된 모든 리소스를 제거하려면:

1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택한 다음 가장 최근 파이프라인을 선택합니다.
1. **destroy-environment** 작업 옆에서 **수동 작업** ({{< icon name="status_manual" >}})을 선택합니다.

## Civo 지원 {#civo-support}

이 Civo 통합은 Civo에서 지원합니다. 지원 요청을 [Civo 지원](https://www.civo.com/contact)으로 보냅니다.
