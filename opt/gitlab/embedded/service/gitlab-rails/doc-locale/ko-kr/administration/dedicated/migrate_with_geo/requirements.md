---
stage: GitLab Dedicated
group: Environment Automation
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Geo 복제 시작 전에 완료해야 할 전제 조건 및 결정 사항입니다.
title: Geo 마이그레이션 요구 사항
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Dedicated

{{< /details >}}

GitLab Self-Managed 인스턴스에서 GitLab Dedicated로의 Geo 복제 시작 전에 다음 요구 사항을 충족해야 합니다. GitLab 마이그레이션 팀이 검색 단계에서 각 요구 사항을 사용자와 확인합니다.

아래의 각 요구 사항은 무엇이 참이어야 하는지, 그리고 이를 충족시키는 방법을 다룹니다. 완료 순서 및 마이그레이션에서의 위치는 [준비](process.md#preparation)를 참조하세요. 일부 요구 사항을 완료하는 데는 몇 주가 걸리므로 가능한 한 빨리 시작합니다.

## 인스턴스 결정 {#instance-decisions}

[GitLab Dedicated 인스턴스를 생성](../create_instance/_index.md)할 때 표준 인스턴스 결정을 내립니다. 이 작업은 각 필드와 수락되는 값을 문서화합니다. 이러한 결정 중 두 가지는 Geo 마이그레이션에서 추가 가중치를 가집니다:

- AWS 리전입니다. 원본 인스턴스가 이미 AWS에서 실행 중인 경우 기본 리전을 원본과 동일한 AWS 리전에 배치하면 마이그레이션 연결이 간단해집니다.
- 진행 중인 액세스 방법입니다. AWS PrivateLink를 연결성에 사용하는 경우 기존 AWS 인프라와 일치하는 두 가용 영역 ID를 선택합니다. IPsec 사이트 간 VPN은 진행 중인 액세스에서 지원되지 않지만 마이그레이션 기간 중에는 사용할 수 있습니다. 자세한 내용은 [네트워크 보안](../configure_instance/network_security.md)을 참조하세요.

> [!warning]
> GitLab이 인스턴스를 프로비저닝한 후 AWS 리전, 가용 영역 ID 또는 고객 관리 암호화 키 구성을 변경할 수 없습니다. 프로비저닝을 시작하기 전에 이 결정을 확인합니다.

## 도메인 전략 {#domain-strategy}

사용자 정의 도메인을 사용할지 GitLab 제공 도메인을 사용할지 결정합니다:

- 사용자 정의 도메인을 사용하면 마이그레이션 후에도 사용자가 동일한 호스트명을 계속 사용합니다. 이슈 및 머지 리퀘스트 설명, 댓글, 러너 구성, 스크립트, 사용자가 구성한 Git 리모트를 포함하여 해당 호스트명에 대한 기존 참조가 계속 확인됩니다. KAS 및 GitLab Pages와 같이 자체 호스트명을 가진 엔드포인트는 여전히 변경됩니다.
- GitLab 제공 도메인을 사용하면 호스트명이 변경되고 전환 후 이전 호스트명에 대한 참조가 확인되지 않습니다. 이들을 업데이트할 계획을 세웁니다.
- 사용자 정의 도메인은 인증서를 발급할 수 있도록 도메인을 공개적으로 확인할 수 있어야 합니다. IP 허용 목록으로 액세스를 제한할 수 있습니다. 공개 DNS 레코드 자체는 액세스 권한을 부여하지 않습니다.
- GitLab 인스턴스에 사용자 정의 도메인을 사용하는 경우 컨테이너 레지스트리 및 Kubernetes용 GitLab 에이전트 서버(KAS)에도 사용하여 호스트명을 일관되게 유지합니다.
- GitLab Pages는 사용자 정의 도메인을 지원하지 않습니다. Pages 콘텐츠는 GitLab Dedicated Pages 도메인에서 제공됩니다.

자세한 내용은 [사용자 정의 도메인](../configure_instance/network_security.md#custom-domains)과 배송 키트 [사용자 정의 도메인에 대한 DNS 요구 사항](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#321-dns-requirements-around-byod)을 참조하세요.

## 원본 인스턴스 요구 사항 {#source-instance-requirements}

GitLab Dedicated로의 복제가 시작되기 전에 인스턴스를 Geo 기본 사이트로 구성합니다. 검증은 기존 데이터에 대한 체크섬을 생성하여 데이터 문제를 조기에 표시하므로 가능한 한 빨리 시작합니다.

자세한 내용은 [Geo](../../geo/_index.md)와 배송 키트 [고객 기본 인스턴스의 Geo 활성화](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#41-geo-activation-on-customer-primary-instance)를 참조하세요.

## 데이터베이스 읽기 복제본 {#database-read-replicas}

GitLab Dedicated는 원본 데이터베이스의 PostgreSQL 읽기 복제본에 도달해야 합니다. Geo가 GitLab Dedicated 사전 프로덕션 테넌트 및 프로덕션 테넌트에 병렬로 동기화되므로 하나는 프로덕션 경로용, 하나는 사전 프로덕션 경로용 두 개의 복제본을 제공합니다.

각 복제본은 마이그레이션 연결을 통해 GitLab Dedicated에서 도달 가능해야 하며 정상 원본에서 스트리밍해야 합니다.

복제본 제공 방법은 원본 데이터베이스가 실행되는 위치에 따라 다릅니다. 원본이 AWS에 있는 경우 공개 [마이그레이션 PrivateLink Terraform 모듈](https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/customer-tools/terraform-migration-privatelink)은 읽기 복제본을 모두 생성하고 PrivateLink를 통해 이들에 대한 액세스를 제공하므로 가장 직관적인 옵션입니다.

자세한 내용은 배송 키트 [RDS 읽기 복제본 및 GitLab에 대한 아웃바운드 PrivateLink](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#451-outbound-privatelinks-to-rds-read-replica-and-gitlab)를 참조하세요.

### AWS RDS에 이미 있는 원본 {#source-already-on-aws-rds}

2개의 RDS 읽기 복제본을 직접 생성합니다.

### AWS에서 RDS 없이 실행 중인 원본 {#source-running-in-aws-without-rds}

GitLab은 마이그레이션 전에 원본 데이터베이스를 백업하고 AWS RDS for PostgreSQL로 복원한 후 여기에 2개의 읽기 복제본을 생성할 것을 권장합니다. RDS 기본 읽기 복제본은 생성 및 관리가 더 간단합니다.

RDS로 이동하려면 덤프 및 복원이 실행되는 동안 가동 중지 시간이 있는 계획된 유지보수 기간이 필요합니다. 데이터베이스 볼륨에 따라 해당 기간을 조정합니다.

### 다른 클라우드 또는 AWS에 없는 원본 {#source-on-another-cloud-or-not-in-aws}

AWS RDS는 필수가 아닙니다. 예를 들어 Google Cloud SQL 또는 Azure Database for PostgreSQL과 같이 자신의 환경에서 2개의 도달 가능한 읽기 복제본을 제공합니다.

## 객체 스토리지 {#object-storage}

Geo 복제가 시작되기 전에 사용 중인 모든 데이터 유형이 객체 스토리지에 있어야 합니다. GitLab Dedicated는 객체 스토리지를 사용하고 Geo 보조 사이트는 기본 사이트와 동일한 스토리지 방법을 사용해야 하므로 로컬 스토리지에 남아 있는 파일은 마이그레이션할 수 없습니다. 자세한 내용은 [Geo를 사용한 객체 스토리지](../../geo/replication/object_storage.md)를 참조하세요.

객체 스토리지로의 마이그레이션은 대부분의 데이터 유형에 대해 가동 중지 시간이 필요하지 않습니다.

각 데이터 유형에 대한 마이그레이션 절차는 [객체 스토리지로 마이그레이션](../../object_storage.md#migrate-to-object-storage)을 참조하세요. 마이그레이션 순서는 배송 키트 [객체 스토리지 마이그레이션](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#48-object-storage-migration)을 참조하세요.

### 객체 스토리지에 대한 비공개 액세스 {#private-access-to-object-storage}

객체 스토리지가 프록시 다운로드를 사용하는 경우 공개 [객체 스토리지 비공개 액세스 도구](https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/customer-tools/object-storage-private-access)를 사용하여 비공개 Amazon S3 인터페이스 엔드포인트를 구성할 수 있습니다.

## 리포지토리 스토리지 {#repository-storage}

GitLab Dedicated는 3개의 Gitaly 스토리지 이름을 지원합니다: `default`, `storage2`, 그리고 `storage3`. 인스턴스가 다른 스토리지 이름을 사용하는 경우 전환하기 전에 리포지토리를 지원되는 이름으로 이동합니다.

자세한 내용은 [리포지토리 스토리지](../create_instance/storage_types.md#repository-storage)와 배송 키트 [Gitaly 리포지토리 스토리지 변경](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#47-gitaly-repository-storage-changes)을 참조하세요.

## 마이그레이션 연결 {#migration-connectivity}

마이그레이션 중에 GitLab Dedicated는 원본 GitLab 인스턴스 및 2개의 데이터베이스 읽기 복제본에 도달해야 합니다.

원본이 AWS에 있는 경우 공개 인터넷이 아닌 AWS PrivateLink를 통해 연결하고 GitLab Dedicated 기본 리전을 원본과 동일한 AWS 리전에 배치합니다. 자신의 AWS 계정에서 PrivateLink 경로를 설정합니다. 경로는 프로덕션 경로 및 사전 프로덕션 경로 모두에 대한 네트워크 로드 밸런서 및 VPC 엔드포인트 서비스로 구성됩니다. 공개 [인바운드 PrivateLink Terraform 모듈](https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/customer-tools/terraform-inbound-privatelink)은 인바운드 PrivateLink를 생성하고 마이그레이션 PrivateLink Terraform 모듈은 마이그레이션 연결을 준비합니다.

원본이 AWS에 없는 경우 다음을 수행할 수 있습니다:

- 자신이 소유한 AWS 계정으로 연결하고 거기서 AWS PrivateLink를 사용합니다.
- 마이그레이션 기간에 [IPsec 사이트 간 VPN](#ipsec-site-to-site-vpn)을 사용합니다.
- 원본 인스턴스 및 읽기 복제본에 인터넷 액세스를 제공합니다.

마이그레이션 팀과 설계를 확인합니다.

자세한 내용은 배송 키트 [Geo 동기화 연결](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#45-geo-sync-connectivity)을 참조하세요.

### IPsec 사이트 간 VPN {#ipsec-site-to-site-vpn}

PrivateLink가 옵션이 아닌 경우 GitLab은 마이그레이션 기간 동안 네트워크와 GitLab Dedicated 테넌트 간에 AWS 사이트 간 VPN을 설정할 수 있습니다. 마이그레이션 완료 후 VPN은 진행 중인 액세스에서 지원되지 않습니다.

VPN은 정적 라우팅을 사용합니다. BGP 동적 라우팅은 지원되지 않으므로 미리 어느 서브넷이 액세스를 필요로 하는지 알아야 하며 VPN 엔드포인트의 공개 IP 주소와 함께 제공합니다. GitLab은 중복성을 위해 2개의 IPsec 터널을 포함하는 연결의 AWS 측면을 생성한 다음 자신의 VPN 장치에 적용할 구성을 전송합니다.

준비하려면 다음을 수집합니다:

- VPN 엔드포인트의 공개 IP 주소
- GitLab Dedicated에 대한 액세스가 필요한 서브넷
- GitLab이 이를 위한 구성을 생성할 수 있도록 VPN 장치의 제조사 및 모델

GitLab은 GitLab Dedicated 측면에서 NAT(네트워크 주소 변환)를 적용하지 않습니다. GitLab은 GitLab Dedicated가 연결하는 IP 범위를 공유하며, 주소 지정에 따라 필요한 경우 자신의 네트워크에서 변환할 수 있습니다. 마이그레이션이 GitLab Dedicated에서 인스턴스 및 읽기 복제본으로의 한 방향 연결만 필요하므로 들어오는 원본 주소만 변환합니다.

설정 절차는 배송 키트 [IPsec VPN 액세스](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#452-ipsec-vpn-access)를 참조하세요.

## 통합을 위한 아웃바운드 연결 {#outbound-connectivity-for-integrations}

다음과 같이 아웃바운드 대상을 준비합니다:

- 웹후크 및 통합을 IP 주소가 아닌 호스트명으로 대상으로 지정합니다.
- 모든 비공개 주소에 연결이 필요하다고 가정하기 전에 아웃바운드 대상 목록을 검토합니다. 루프백 주소, 자체 참조 및 클러스터 내부 주소는 종종 실제 외부 엔드포인트가 아닙니다.

GitLab Dedicated는 최대 10개의 아웃바운드 PrivateLink 엔드포인트를 지원합니다. 더 많은 비공개 대상이 도달 가능성을 필요로 하는 경우 공개 [아웃바운드 프록시 Terraform 모듈](https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/customer-tools/terraform-outbound-proxy)을 사용하여 단일 연결 뒤에 여러 백엔드를 통합합니다. 이 모듈은 네트워크 로드 밸런서 뒤에 고가용성 NGINX 프록시를 배포하고 HTTPS, HTTP 및 SMTP 백엔드를 통합할 수 있습니다.

아웃바운드 대상을 인벤토리하려면 공개 [GitLab 검색 도구 키트](https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/customer-tools/gitlab-discovery-toolkit)를 사용합니다.

[테스트 기간](process.md#testing-period) 중에 모든 아웃바운드 대상을 테스트합니다. 아웃바운드 연결 문제는 가장 일반적인 발견 중 일부이며 테스트 기간이 이들을 표시할 때입니다.

자세한 내용은 [아웃바운드 PrivateLink 연결](../configure_instance/network_security.md#outbound-privatelink-connections) 및 배송 키트 [웹후크 및 통합](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#316-webhooks-and-integrations)을 참조하세요.

## SaaS 통합을 위한 인바운드 액세스 {#inbound-access-for-saas-integrations}

IP 허용 목록을 사용하는 경우 티켓팅 시스템, 채팅 통합 또는 GitLab API를 호출하는 CI/CD 서비스와 같이 GitLab Dedicated 인스턴스에 도달해야 하는 외부 SaaS 서비스에 대해 허용 목록 예외를 추가합니다.

전환하기 전에 이 서비스를 인벤토리합니다. 허용 목록에 없는 서비스의 요청은 차단됩니다.

자세한 내용은 [IP 허용 목록](../configure_instance/network_security.md#ip-allowlist)을 참조하세요.

## 해결할 기능 {#features-to-remediate}

인스턴스를 [사용 불가능한 기능](../../../subscriptions/gitlab_dedicated/_index.md#unavailable-features) 목록과 비교하여 확인하고 전환하기 전에 사용하는 모든 항목에 대해 대체를 배치합니다. 목록을 진행하기 위한 지침은 배송 키트 [지원되지 않는 나머지 기능](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#3111-remaining-unsupported-features)을 참조하세요.

2개 항목은 나머지보다 더 많은 계획 시간이 필요하며 GitLab은 각각에 대해 도구 또는 절차를 제공합니다:

- LDAP에서 SAML 또는 OpenID Connect(OIDC) ID 공급자로 이동하는 것은 종종 준비의 가장 긴 단일 항목입니다. 자세한 내용은 [LDAP에서 SAML로 이동](#move-from-ldap-to-saml)을 참조하세요.
- GitLab Pages 사용자 정의 도메인입니다. 이는 GitLab Dedicated에서 지원하지 않습니다. Pages 콘텐츠는 GitLab Dedicated Pages 도메인에서 제공됩니다. 임시 전환을 위해 공개 [Pages 리디렉션 Terraform 모듈](https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/customer-tools/terraform-gitlab-pages-redirect)을 사용할 수 있으며, 이는 기존 인증서 및 DNS 이름을 유지하고 새 URL로 리디렉션을 반환합니다. 이 모듈은 임시 지원이며 영구 솔루션이 아닙니다.

기본 `/-/kubernetes-agent` 경로가 GitLab Dedicated에 존재하지 않으므로 GitLab Kubernetes 에이전트를 새로운 KAS URL에 다시 등록해야 합니다.

### LDAP에서 SAML로 이동 {#move-from-ldap-to-saml}

LDAP에서 이동하는 것은 종종 준비의 가장 긴 단일 항목이므로 빨리 시작합니다.

GitLab Dedicated에서 ID 공급자를 구성하려면 [SAML](../configure_instance/authentication/saml.md) 또는 [OpenID Connect](../configure_instance/authentication/openid_connect.md)를 참조하세요.

LDAP 그룹 동기화를 사용하는 경우 [SAML 그룹 동기화](../../../user/group/saml_sso/group_sync.md)로 변환하여 그룹 멤버십을 유지할 수 있습니다. 변환 절차 및 GitLab Professional Services에서 사용하는 스크립트는 배송 키트 [SSO 구성](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md#44-sso-configuration)을 참조하세요.

## 관련 항목 {#related-topics}

- [GitLab Dedicated로의 Geo 마이그레이션](_index.md)
- [Geo 마이그레이션 비밀 수집](secrets.md)
- [Geo 마이그레이션 프로세스](process.md)
- [마이그레이션 후 활동](post_cutover.md)
