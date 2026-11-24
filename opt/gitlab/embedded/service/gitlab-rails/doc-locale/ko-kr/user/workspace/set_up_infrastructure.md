---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 워크스페이스를 지원하기 위해 필요한 인프라를 온디맨드 클라우드 기반 개발 환경으로 생성합니다.
title: '튜토리얼: AWS에서 워크스페이스 인프라 설정'
---

<!-- vale gitlab_base.FutureTense = NO -->

이 튜토리얼에서는 [OpenTofu](https://opentofu.org/)를 사용하여 AWS에서 GitLab 워크스페이스 인프라 설정 과정을 안내합니다. OpenTofu는 코드 기반 인프라(IaC)를 통한 Terraform의 오픈소스 포크입니다.

## 시작하기 전에 {#before-you-begin}

이 튜토리얼을 따르려면 다음이 필요합니다:

- Amazon Web Services(AWS) 계정
- 워크스페이스 환경의 도메인 이름

GitLab 워크스페이스 인프라를 설정하려면:

1. [리포지토리 포크](#fork-the-repository)
1. [AWS 자격증명 설정](#set-up-aws-credentials)
1. [도메인 및 인증서 준비](#prepare-domain-and-certificates)
1. [필수 키 생성](#create-required-keys)
1. [Kubernetes용 GitLab 에이전트 토큰 생성](#create-a-gitlab-agent-for-kubernetes-token)
1. [GitLab OAuth 구성](#configure-gitlab-oauth)
1. [CI/CD 변수 구성](#configure-cicd-variables)
1. [Kubernetes용 GitLab 에이전트 구성 업데이트](#update-the-gitlab-agent-for-kubernetes-configuration)
1. [파이프라인 실행](#run-the-pipeline)
1. [DNS 레코드 구성](#configure-dns-records)
1. [에이전트 허용](#authorize-the-agent)
1. [워크스페이스 생성 및 설정 확인](#create-a-workspace-and-verify-setup)

## 리포지토리 포크 {#fork-the-repository}

먼저 인프라 설정 리포지토리의 자체 복사본을 생성하여 환경에 맞게 구성합니다.

> [!note]
> 개인 네임스페이스의 프로젝트에서 워크스페이스를 생성할 수 없습니다. 대신 최상위 그룹 또는 하위 그룹으로 리포지토리를 포크합니다.

리포지토리를 포크하려면:

1. [Workspaces Infrastructure Setup AWS](https://gitlab.com/gitlab-org/workspaces/examples/workspaces-infrastructure-setup-aws) 리포지토리로 이동합니다.
1. [포크 생성](../project/repository/forking_workflow.md#create-a-fork)을 수행합니다.

## AWS 자격 증명 설정 {#set-up-aws-credentials}

다음으로 인프라를 올바르게 프로비저닝할 수 있도록 AWS에서 필요한 권한을 설정합니다.

AWS 자격증명을 설정하려면:

1. [IAM 사용자](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users.html) 또는 [IAM 역할](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html)을 생성합니다.
1. 다음 권한을 할당합니다:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "VisualEditor0",
         "Effect": "Allow",
         "Action": [
           "ec2:*",
           "eks:*",
           "elasticloadbalancing:*",
           "autoscaling:*",
           "cloudwatch:*",
           "logs:*",
           "kms:DescribeKey",
           "kms:TagResource",
           "kms:UntagResource",
           "kms:ListResourceTags",
           "kms:CreateKey",
           "kms:CreateAlias",
           "kms:ListAliases",
           "kms:DeleteAlias",
           "iam:AddRoleToInstanceProfile",
           "iam:AttachRolePolicy",
           "iam:CreateInstanceProfile",
           "iam:CreateRole",
           "iam:CreateServiceLinkedRole",
           "iam:GetRole",
           "iam:ListAttachedRolePolicies",
           "iam:ListRolePolicies",
           "iam:ListRoles",
           "iam:PassRole",
           "iam:DetachRolePolicy",
           "iam:ListInstanceProfilesForRole",
           "iam:DeleteRole",
           "iam:CreateOpenIDConnectProvider",
           "iam:CreatePolicy",
           "iam:TagOpenIDConnectProvider",
           "iam:GetPolicy",
           "iam:GetPolicyVersion",
           "iam:GetOpenIDConnectProvider",
           "iam:DeleteOpenIDConnectProvider",
           "iam:ListPolicyVersions",
           "iam:DeletePolicy"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

1. [액세스 키 생성](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)을 수행합니다.
1. 액세스 키 ID 및 비밀 액세스 키를 저장합니다. 나중에 CI/CD 변수를 구성할 때 필요합니다.

## 도메인 및 인증서 준비 {#prepare-domain-and-certificates}

워크스페이스가 액세스 가능하도록 하려면 도메인과 연결을 보호하는 TLS 인증서가 필요합니다.

도메인 및 인증서를 준비하려면:

1. 워크스페이스 환경의 도메인을 구매하거나 기존 도메인을 사용합니다.
1. 다음의 TLS 인증서를 생성합니다:
   - GitLab 워크스페이스 프록시 도메인입니다. 예를 들어, `workspaces.example.dev`입니다.
   - GitLab 워크스페이스 프록시 와일드카드 도메인입니다. 예를 들어, `*.workspaces.example.dev`입니다.

자세한 내용은 [TLS 인증서 생성](set_up_gitlab_agent_and_proxies.md#generate-tls-certificates)을 참조하세요.

## 필수 키 생성 {#create-required-keys}

이제 인증 및 SSH 연결을 위한 보안 키를 생성해야 합니다.

필수 키를 생성하려면:

1. 임의의 문자, 숫자 및 특수 문자로 구성된 서명 키를 생성합니다. 예를 들어 다음을 실행합니다:

   ```shell
   openssl rand -base64 32
   ```

1. SSH 호스트 키를 생성합니다:

   ```shell
   ssh-keygen -f ssh-host-key -N '' -t rsa
   ```

## Kubernetes용 GitLab 에이전트 토큰 생성 {#create-a-gitlab-agent-for-kubernetes-token}

Kubernetes용 GitLab 에이전트는 AWS Kubernetes 클러스터를 GitLab에 연결합니다.

에이전트의 토큰을 생성하려면:

1. 그룹으로 이동합니다.
1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. **클러스터 연결**을 선택합니다.
1. 에이전트의 이름을 입력하고 나중에 사용하기 위해 저장합니다. 예를 들어, `gitlab-workspaces-agentk-eks`입니다.
1. **생성하고 등록**을 선택합니다.
1. 토큰 및 GitLab Relay(KAS) 주소를 저장하여 나중에 사용합니다.
1. **계속**을 선택합니다.

## GitLab OAuth 구성 {#configure-gitlab-oauth}

다음으로 워크스페이스에 안전하게 액세스할 수 있도록 OAuth 인증을 설정합니다.

GitLab OAuth를 구성하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **응용 프로그램**을 선택합니다.
1. **OAuth 어플리케이션**까지 스크롤합니다.
1. **새 애플리케이션 추가**를 선택합니다.
1. 다음 설정을 업데이트합니다:

   - 이름: GitLab 워크스페이스 프록시
   - 리다이렉트 URI: 예를 들어, `https://workspaces.example.dev/auth/callback`입니다. 사용자 정의 도메인으로 바꿉니다.
   - **비공개** 확인란을 선택합니다.
   - 범위: `api`, `read_user`, `openid`, 및 `profile`.

1. **애플리케이션 저장**을 선택합니다.
1. CI/CD 변수의 **애플리케이션 ID** 및 **비밀**을 저장합니다.
1. **계속**을 선택합니다.

## CI/CD 변수 구성 {#configure-cicd-variables}

이제 인프라 파이프라인을 실행할 수 있도록 CI/CD 구성에 필요한 변수를 추가해야 합니다.

CI/CD 변수를 구성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **변수**를 펼칩니다.
1. **프로젝트 변수** 섹션에서 다음 필수 변수를 추가합니다:

   | 변수                                       | 값 |
   |------------------------------------------------|-------|
   | `AWS_ACCESS_KEY_ID`                            | AWS 액세스 키 ID |
   | `AWS_SECRET_ACCESS_KEY`                        | AWS 비밀 액세스 키 |
   | `TF_VAR_agent_token`                           | Kubernetes용 GitLab 에이전트 토큰 |
   | `TF_VAR_kas_address`                           | GitLab Relay(KAS) 주소 GitLab Self-Managed 인스턴스를 사용하는 경우 필수입니다. 예를 들어, `grpcs://kas.gitlab.com`입니다. |
   | `TF_VAR_workspaces_proxy_auth_client_id`       | OAuth 어플리케이션 클라이언트 ID |
   | `TF_VAR_workspaces_proxy_auth_client_secret`   | OAuth 어플리케이션 비밀 |
   | `TF_VAR_workspaces_proxy_auth_redirect_uri`    | OAuth 콜백 URL 예를 들어, `https://workspaces.example.dev/auth/callback`입니다. |
   | `TF_VAR_workspaces_proxy_auth_signing_key`     | 생성된 서명 키 |
   | `TF_VAR_workspaces_proxy_domain`               | 워크스페이스 프록시의 도메인 |
   | `TF_VAR_workspaces_proxy_domain_cert`          | 프록시 도메인의 TLS 인증서 |
   | `TF_VAR_workspaces_proxy_domain_key`           | 프록시 도메인의 TLS 키 |
   | `TF_VAR_workspaces_proxy_ssh_host_key`         | 생성된 SSH 호스트 키 |
   | `TF_VAR_workspaces_proxy_wildcard_domain`      | 워크스페이스의 와일드카드 도메인 |
   | `TF_VAR_workspaces_proxy_wildcard_domain_cert` | 와일드카드 도메인의 TLS 인증서 |
   | `TF_VAR_workspaces_proxy_wildcard_domain_key`  | 와일드카드 도메인의 TLS 키 |

1. 선택 사항. 배포를 사용자 지정하기 위해 다음 변수를 추가합니다:

   | 변수                                     | 값 |
   |----------------------------------------------|-------|
   | `TF_VAR_region`                              | AWS 리전 |
   | `TF_VAR_zones`                               | AWS 가용 영역 |
   | `TF_VAR_name`                                | 리소스의 이름 접두사 |
   | `TF_VAR_cluster_endpoint_public_access`      | 클러스터 엔드포인트에 대한 공개 액세스 |
   | `TF_VAR_cluster_node_instance_type`          | Kubernetes 노드의 EC2 인스턴스 유형 |
   | `TF_VAR_cluster_node_count_min`              | 작업자 노드의 최소 수 |
   | `TF_VAR_cluster_node_count_max`              | 작업자 노드의 최대 수 |
   | `TF_VAR_cluster_node_count`                  | 작업자 노드의 수 |
   | `TF_VAR_cluster_node_labels`                 | 클러스터 노드에 적용할 레이블 맵 |
   | `TF_VAR_agent_namespace`                     | 에이전트의 Kubernetes 네임스페이스 |
   | `TF_VAR_workspaces_proxy_namespace`          | 워크스페이스 프록시의 Kubernetes 네임스페이스 |
   | `TF_VAR_workspaces_proxy_ingress_class_name` | Ingress 클래스 이름 |
   | `TF_VAR_ingress_nginx_namespace`             | Ingress-NGINX의 Kubernetes 네임스페이스 |

잘했습니다! 인프라 배포를 위한 모든 필수 변수를 구성했습니다.

## Kubernetes용 GitLab 에이전트 구성 업데이트 {#update-the-gitlab-agent-for-kubernetes-configuration}

이제 워크스페이스를 지원하도록 Kubernetes용 GitLab 에이전트를 구성해야 합니다.

에이전트 구성을 업데이트하려면:

1. 포크된 리포지토리에서 `.gitlab/agents/gitlab-workspaces-agentk-eks/config.yaml` 파일을 엽니다.

   > [!note]
   > `config.yaml` 파일이 포함된 디렉토리는 [Kubernetes용 GitLab 에이전트 토큰 생성](#create-a-gitlab-agent-for-kubernetes-token) 단계에서 생성한 에이전트 이름과 일치해야 합니다.

1. 파일을 다음 필수 필드로 업데이트합니다:

   ```yaml
   remote_development:
     enabled: true
     dns_zone: "workspaces.example.dev"  # Replace with your domain
   ```

   더 많은 구성 옵션을 보려면 [워크스페이스 설정](settings.md)을 참조하세요.

1. 이 변경 사항을 리포지토리에 커밋하고 푸시합니다.

## 파이프라인 실행 {#run-the-pipeline}

이제 인프라를 배포할 시간입니다. CI/CD 파이프라인을 실행하여 AWS에서 필요한 모든 리소스를 생성합니다.

파이프라인을 실행하려면:

1. GitLab 프로젝트에서 새 파이프라인을 생성합니다:
   1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
   1. **새 파이프라인**을 선택한 후 **새 파이프라인**을 다시 선택하여 확인합니다.
1. `plan` 작업이 성공하는지 확인한 후 `apply` 작업을 수동으로 트리거합니다.

OpenTofu 코드가 실행되면 AWS에서 다음 리소스를 생성합니다:

- 가상 프라이빗 클라우드(VPC)
- Elastic Kubernetes Service(EKS) 클러스터
- Kubernetes Helm 릴리스용 GitLab 에이전트
- GitLab 워크스페이스 프록시 Helm 릴리스
- Ingress NGINX Helm 릴리스

훌륭합니다! 인프라가 이제 배포 중입니다. 완료되는 데 시간이 걸릴 수 있습니다.

## DNS 레코드 구성 {#configure-dns-records}

인프라가 배포되었으므로 이제 DNS 레코드를 구성하여 새 환경을 가리키도록 해야 합니다.

DNS 레코드를 구성하려면:

1. 파이프라인 출력에서 Ingress-NGINX 로드 밸런서 주소를 얻습니다:

   ```shell
   kubectl get services -n ingress-nginx ingress-nginx-controller
   ```

1. 도메인을 이 주소로 가리키는 DNS 레코드를 생성합니다. 예를 들어:
   - `workspaces.example.dev` → 로드 밸런서 IP 주소
   - `*.workspaces.example.dev` → 로드 밸런서 IP 주소

## 에이전트 허용 {#authorize-the-agent}

다음으로 Kubernetes용 GitLab 에이전트를 허용하여 GitLab 인스턴스에 연결합니다.

에이전트를 허용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **작업공간**을 선택합니다.
1. **그룹 에이전트** 섹션에서 **모든 에이전트** 탭을 선택합니다.
1. 사용 가능한 에이전트 목록에서 상태가 **차단됨**인 에이전트를 찾고 **허용**을 선택합니다.
1. 확인 대화상자에서 **에이전트 허용**을 선택합니다.

## 워크스페이스 생성 및 설정 확인 {#create-a-workspace-and-verify-setup}

마지막으로 테스트 워크스페이스를 생성하여 모든 것이 올바르게 작동하는지 확인합니다.

워크스페이스 설정을 확인하려면:

1. [워크스페이스 생성](configuration.md#create-a-workspace)의 단계를 따라 새 워크스페이스를 생성합니다.
1. 프로젝트에서 **코드**를 선택합니다.
1. 워크스페이스 이름을 선택합니다.
1. Web IDE를 열거나 터미널에 액세스하거나 프로젝트 파일을 변경하여 워크스페이스와 상호 작용합니다.

축하합니다! AWS에서 GitLab 워크스페이스 인프라를 성공적으로 설정했습니다. 이제 사용자가 프로젝트의 개발 워크스페이스 환경을 생성할 수 있습니다.

문제가 발생하면 로그에서 추가 세부 정보를 확인하고 [워크스페이스 문제 해결](workspaces_troubleshooting.md)을 참조하세요.

## 관련 항목 {#related-topics}

- [워크스페이스](_index.md)
- [워크스페이스 구성](configuration.md)
- [워크스페이스 설정](settings.md)
- [튜토리얼: 임의의 사용자 ID를 지원하는 사용자 지정 워크스페이스 이미지 생성](create_image.md)
