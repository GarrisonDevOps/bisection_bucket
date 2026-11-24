---
stage: GitLab Dedicated
group: Environment Automation
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab Self-Managed에서 GitLab Dedicated로 Geo를 사용하여 마이그레이션합니다.
title: Geo를 사용하여 GitLab Dedicated로 마이그레이션
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Dedicated

{{< /details >}}

Geo는 GitLab Self-Managed 인스턴스를 GitLab Dedicated로 복제한 후 기본 사이트로 승격합니다. 이 방법은 리포지토리, 데이터베이스 레코드, 객체 스토리지 콘텐츠를 포함한 가장 완전한 데이터 세트를 마이그레이션합니다.

인스턴스는 복제 전체 기간 동안 서비스 상태를 유지합니다. 마이그레이션 자체는 전환 기간 중에만 다운타임이 필요합니다. 그러나 사전에 소스 인스턴스를 준비하려면 별도의 다운타임이 필요할 수 있습니다.

GitLab 전문 서비스는 사용자와 함께 마이그레이션을 실행합니다. Geo는 소스가 GitLab Self-Managed 인스턴스인 경우에만 적용됩니다. GitLab.com에서 마이그레이션하거나 다른 소스 제어 관리 시스템에서 마이그레이션하거나 전체 인스턴스가 아닌 개별 그룹 및 프로젝트를 마이그레이션하려면 [GitLab Dedicated로 마이그레이션](../../../subscriptions/gitlab_dedicated/_index.md#migrate-to-gitlab-dedicated)을 참조하세요.

## 마이그레이션 단계 {#migration-phases}

Geo 마이그레이션은 다음 단계에서 실행됩니다:

| 단계 | 실행 내용 | 실행자 |
|-------|--------------|----------|
| 검색 및 계획 | GitLab Dedicated 구매를 완료하기 전에 솔루션 아키텍트 또는 계정 담당자가 환경에 대한 정보를 수집하도록 도와줍니다. GitLab은 이 정보를 사용하여 마이그레이션 가능성, 규모 및 타임라인을 평가합니다. | 사용자 및 GitLab |
| 인스턴스 생성 | 구매가 완료된 후 GitLab Dedicated 인스턴스를 직접 생성하거나 원하는 경우 GitLab 전문 서비스에서 생성할 수 있습니다. | 사용자 |
| 준비 | 데이터를 객체 스토리지로 이동하고, 리포지토리 스토리지 이름을 정렬하고, 마이그레이션 연결을 구축하고, 데이터베이스 읽기 복제본을 생성합니다. 이 작업을 직접 또는 GitLab과 함께 수행할 수 있습니다. 자세한 내용은 [Geo 마이그레이션 요구 사항](requirements.md) 및 [Geo 마이그레이션 암호 수집](secrets.md)을 참조하세요. | 사용자 또는 사용자 및 GitLab |
| Geo 복제 | GitLab이 데이터를 새 GitLab Dedicated 인스턴스로 복제하는 동안 기존 인스턴스는 서비스 상태를 유지합니다. 자세한 내용은 [Geo 마이그레이션 프로세스](process.md)를 참조하세요. | GitLab |
| 전환 및 테스트 | 사전 프로덕션 전환으로 프로세스를 연습하고 결과를 테스트한 후 프로덕션 전환으로 마이그레이션을 완료합니다. | 사용자 및 GitLab |
| 마이그레이션 후 활동 | GitLab은 나머지 업그레이드를 적용하고 사용자와 합의한 일정에 따라 고급 검색 등의 기능을 활성화합니다. GitLab Dedicated 라이선스를 추가합니다. 자세한 내용은 [마이그레이션 후 활동](post_cutover.md)을 참조하세요. | 사용자 및 GitLab |

GitLab 전문 서비스는 이러한 단계 전체에 걸쳐 단계별 기술 절차 및 스크립트를 위해 [Geo 마이그레이션 전달 키트](https://gitlab.com/gitlab-org/professional-services-automation/delivery-kits/migration-delivery-kits/migration-delivery-kit/-/blob/main/Geo/dedicated.md)를 사용합니다.

검색부터 프로덕션 전환까지 여러 개월을 계획하세요. GitLab은 사용자와 타임라인을 확인합니다. 이는 보유한 데이터의 양과 환경에 필요한 준비 작업의 양에 따라 달라집니다.

> [!note]
> 자신의 환경이 하나만 필요합니다. 단일 프로덕션 인스턴스에서 마이그레이션합니다. GitLab은 사전 프로덕션 테넌트와 프로덕션 테넌트를 모두 프로비저닝하며, 사전 프로덕션 테넌트는 마이그레이션 기간 중에만 존재하므로 하나의 완전한 전환 연습을 실행할 수 있습니다. 직접 구축하거나 유지하지 않습니다.

## 관련 항목 {#related-topics}

- [GitLab Dedicated 아키텍처](../architecture.md)
- [GitLab Dedicated 인스턴스 생성](../create_instance/_index.md)
- [Geo](../../geo/_index.md)
