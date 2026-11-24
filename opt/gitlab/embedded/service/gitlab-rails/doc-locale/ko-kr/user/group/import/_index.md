---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 직접 전송을 사용하여 GitLab 데이터 마이그레이션
description: "직접 연결을 사용하여 GitLab 데이터를 마이그레이션합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 그룹을 마이그레이션할 수 있습니다:

- GitLab Self-Managed 및 GitLab Dedicated에서 GitLab.com으로
- GitLab.com에서 GitLab Self-Managed 및 GitLab Dedicated로
- 한 GitLab Self-Managed 또는 GitLab Dedicated 인스턴스에서 다른 인스턴스로
- 동일한 GitLab 인스턴스에서

직접 전송을 통한 마이그레이션은 그룹의 새로운 복사본을 만듭니다. 그룹을 복사하는 대신 이동하려면 그룹이 동일한 GitLab 인스턴스에 있는 경우 [그룹을 전송](../manage.md#transfer-a-group)할 수 있습니다. 그룹을 마이그레이션하는 대신 전송하는 것이 더 빠르고 더 완전한 옵션입니다.

그룹을 다음과 같은 방법으로 마이그레이션할 수 있습니다:

- 직접 전송(권장).
- 목적지 인스턴스가 소스 인스턴스에 대한 직접 네트워크 연결이 없을 때 객체 스토리지를 통한 [오프라인 전송](../../import/gitlab_instances/offline-transfer-migrations.md).
- [내보내기 파일 업로드](../../project/settings/import_export.md).

GitLab.com에서 GitLab Self-Managed 또는 GitLab Dedicated 인스턴스로 마이그레이션하면 관리자가 인스턴스에 사용자를 만들 수 있습니다.

GitLab Self-Managed 및 GitLab Dedicated에서는 기본적으로 [그룹 항목 마이그레이션](migrated_items.md#migrated-group-items)을 사용할 수 없습니다. 기능을 표시하려면 관리자가 [애플리케이션 설정에서 활성화](../../../administration/settings/import_and_export_settings.md#enable-migration-of-groups-and-projects-by-direct-transfer)할 수 있습니다.

직접 전송을 통한 그룹 마이그레이션은 한 위치에서 다른 위치로 그룹을 복사합니다. 다음과 같이 수행할 수 있습니다.

- 많은 그룹을 한 번에 복사합니다.
- GitLab UI에서 최상위 그룹을 다음으로 복사합니다:
  - 다른 최상위 그룹.
  - 기존의 모든 최상위 그룹의 하위 그룹.
  - GitLab.com을 포함한 다른 GitLab 인스턴스.
- [그룹 및 프로젝트 직접 전송 API](../../../api/bulk_imports.md)에서 최상위 그룹 및 하위 그룹을 이러한 위치로 복사합니다.
- 프로젝트가 있거나 없는 그룹을 복사합니다. 프로젝트가 있는 그룹의 복사는 GitLab.com에서 기본적으로 사용할 수 있습니다.

모든 그룹 및 프로젝트 리소스가 복사되는 것은 아닙니다. 아래의 복사된 리소스 목록을 참조하세요:

- [마이그레이션된 그룹 항목](migrated_items.md#migrated-group-items).
- [마이그레이션된 프로젝트 항목](migrated_items.md#migrated-project-items).

마이그레이션을 시작한 후에는 소스 인스턴스에서 가져온 그룹 또는 프로젝트를 변경하지 않아야 합니다. 이러한 변경 사항이 목적지 인스턴스로 복사되지 않을 수 있기 때문입니다.

직접 전송을 통한 마이그레이션에 대한 피드백을 [피드백 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/284495)에 남기도록 권장합니다.

## 특정 프로젝트 마이그레이션 {#migrating-specific-projects}

GitLab UI에서 직접 전송을 사용하여 그룹을 마이그레이션하면 그룹의 모든 프로젝트가 마이그레이션됩니다. 직접 전송을 사용하여 그룹의 특정 프로젝트만 마이그레이션하려면 [API](../../../api/bulk_imports.md#start-a-group-or-project-migration)를 사용해야 합니다.

## 알려진 이슈 {#known-issues}

- [이슈 406685](https://gitlab.com/gitlab-org/gitlab/-/issues/406685) 때문에 파일명이 255자보다 긴 파일은 마이그레이션되지 않습니다.
- 소스 인스턴스에서 매핑될 때 공유 멤버는 해당 멤버십이 목적지에 이미 존재하지 않으면 목적지에서 직접 멤버로 매핑됩니다. 이는 소스 인스턴스의 최상위 그룹을 목적지 인스턴스의 최상위 그룹으로 가져올 때 소스 최상위 그룹에 필요한 공유 멤버십 계층 구조 세부 사항이 포함되어 있더라도 항상 프로젝트의 직접 멤버로 매핑됨을 의미합니다. 공유 멤버십의 전체 매핑 지원은 [이슈 458345](https://gitlab.com/gitlab-org/gitlab/-/issues/458345)에서 제안되었습니다.
- GitLab 17.0, 17.1 및 17.2에서 가져온 에픽 및 작업 항목은 원본 작성자가 아닌 가져오는 사용자로 매핑됩니다.
- 직접 전송은 다양한 소스 그룹의 그룹 또는 프로젝트를 단일 목적지 그룹으로 통합하는 것을 지원하지 않습니다. 그룹 또는 프로젝트를 통합하려면 마이그레이션 전에 소스 인스턴스에서 재구성하거나 목적지 인스턴스에서 [자리표시자 사용자 재할당이 완료된 후](../../import/mapping/reassignment.md#completing-the-reassignment) 재구성합니다. [이슈 589460](https://gitlab.com/gitlab-org/gitlab/-/work_items/589460)을 참조하세요.
- 목적지 네임스페이스가 소스와 다른 조직에 속하고 어느 한 조직이라도 격리됨으로 표시되면 직접 전송을 통한 마이그레이션이 실패합니다. 자세한 내용은 [이슈 595674](https://gitlab.com/gitlab-org/gitlab/-/issues/595674)를 참조하세요.
- 직접 전송 마이그레이션이 목적지 인스턴스의 허용되지 않은 사용자에게 기여도를 매핑하므로 소스 인스턴스에서 숨겨진 차단된 사용자의 기여도가 목적지 인스턴스에서 다시 나타납니다. 이러한 기여도를 숨기려면 목적지 인스턴스에서 다음 중 하나를 수행합니다:
  - 사용자를 차단합니다.
  - 기여도를 제거합니다. 자세한 내용은 [이슈 508111](https://gitlab.com/gitlab-org/gitlab/-/work_items/508111)을 참조하세요.
- 마이그레이션 중에 참고, 이슈 설명 및 머지 리퀘스트 설명의 URL 참조는 마이그레이션되는 그룹 또는 프로젝트에 속하는 링크(`source_full_path`)에만 다시 작성됩니다. 소스 인스턴스의 다른 그룹 또는 프로젝트를 가리키는 URL은 해당 그룹 또는 프로젝트도 마이그레이션되는 경우에도 다시 작성되지 않습니다. 마이그레이션 후 소스 인스턴스를 여전히 가리키는 외부 링크를 수동으로 업데이트할 수 있습니다.

## 마이그레이션 기간 추정 {#estimating-migration-duration}

직접 전송을 통한 마이그레이션 기간을 추정하는 것은 어렵습니다. 다음 요소가 마이그레이션 기간에 영향을 줍니다:

- 소스 및 목적지 GitLab 인스턴스에서 사용 가능한 하드웨어 및 데이터베이스 리소스. 소스 및 목적지 인스턴스에 더 많은 리소스가 있으면 다음과 같은 이유로 마이그레이션 기간이 단축될 수 있습니다:
  - 소스 인스턴스는 API 요청을 받고 내보낼 엔터티를 추출하고 직렬화합니다.
  - 목적지 인스턴스는 작업을 실행하고 데이터베이스에서 엔터티를 만듭니다.
- 내보낼 데이터의 복잡성과 크기. 예를 들어 1000개의 머지 리퀘스트가 있는 두 개의 다른 프로젝트를 마이그레이션하려고 한다고 가정합니다. 한 프로젝트가 머지 리퀘스트에 훨씬 더 많은 첨부 파일, 주석 및 기타 항목을 가지고 있으면 두 프로젝트는 마이그레이션하는 데 매우 다른 시간이 걸릴 수 있습니다. 따라서 프로젝트의 머지 리퀘스트 수는 프로젝트를 마이그레이션하는 데 얼마나 오래 걸릴지 예측하는 좋은 지표가 아닙니다.

마이그레이션을 안정적으로 추정할 수 있는 정확한 공식은 없습니다. 그러나 프로젝트 {{< glossary-tooltip text="관계" >}}를 가져오는 각 파이프라인 워커의 평균 기간은 프로젝트를 가져오는 데 얼마나 오래 걸릴지에 대한 아이디어를 얻는 데 도움이 될 수 있습니다.

이 컨텍스트에서 관계는 내보낼 수 있는 항목의 유형입니다.

| 프로젝트 리소스 유형       | 레코드를 가져오는 평균 시간(초 단위) |
|:----------------------------|:---------------------------------------------|
| 빈 프로젝트               | 2.4                                          |
| 리포지토리                  | 20                                           |
| 프로젝트 속성          | 1.5                                          |
| 멤버                     | 0.2                                          |
| 레이블                      | 0.1                                          |
| 마일스톤                  | 0.07                                         |
| 배지                      | 0.1                                          |
| 이슈                      | 0.1                                          |
| 스니펫                    | 0.05                                         |
| 스니펫 리포지토리        | 0.5                                          |
| 보드                      | 0.1                                          |
| 머지 리퀘스트              | 1                                            |
| 외부 풀 리퀘스트      | 0.5                                          |
| 보호된 브랜치          | 0.1                                          |
| 프로젝트 기능             | 0.3                                          |
| 컨테이너 만료 정책 | 0.3                                          |
| 서비스 데스크 설정        | 0.3                                          |
| 릴리스                    | 0.1                                          |
| CI 파이프라인                | 0.2                                          |
| 커밋 참고                | 0.05                                         |
| 위키                        | 10                                           |
| 업로드                     | 0.5                                          |
| LFS 객체                 | 0.5                                          |
| 디자인                      | 0.1                                          |
| Auto DevOps                 | 0.1                                          |
| 파이프라인 일정          | 0.5                                          |
| 참조                  | 5                                            |
| 푸시 규칙                   | 0.1                                          |

마이그레이션 기간을 예측하기는 어렵지만 다음과 같은 사항이 관찰되었습니다:

- 100개 프로젝트(19.9천 이슈, 83천 머지 리퀘스트, 100천 개 이상 파이프라인)가 8시간에 마이그레이션되었습니다.
- 1926개 프로젝트(22천 이슈, 160천 머지 리퀘스트, 110만 파이프라인)가 34시간에 마이그레이션되었습니다.

대규모 프로젝트를 마이그레이션하고 있으며 시간 초과 또는 마이그레이션 기간 문제가 발생하면 [마이그레이션 기간 단축](troubleshooting.md#migrations-are-slow-or-timing-out)을 시도하세요.

## 제한 {#limits}

기본 제한은 [직접 전송 마이그레이션 제한](../../../administration/instance_limits.md#direct-transfer-migration)을 참조하세요.

이러한 API를 사용하여 최대 관계 크기 제한을 테스트할 수 있습니다:

- [그룹 관계 내보내기 API](../../../api/group_relations_export.md).
- [프로젝트 관계 내보내기 API](../../../api/project_relations_export.md)

어느 API든 최대 관계 크기 제한보다 큰 파일을 생성하면 그룹 직접 전송 마이그레이션이 실패합니다.

## 표시 규칙 {#visibility-rules}

마이그레이션 후:

- 비공개 그룹과 프로젝트는 비공개로 유지됩니다.
- 내부 그룹 및 프로젝트:
  - 내부 가시성이 [제한](../../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels)되지 않으면 내부 그룹으로 복사될 때 내부 상태를 유지합니다. 이 경우 그룹과 프로젝트가 비공개가 됩니다.
  - 비공개 그룹으로 복사될 때 비공개가 됩니다.
- 공개 그룹 및 프로젝트:
  - 공개 가시성이 [제한](../../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels)되지 않으면 공개 그룹으로 복사될 때 공개 상태를 유지합니다. 이 경우 그룹과 프로젝트가 내부가 됩니다.
  - 내부 가시성이 [제한](../../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels)되지 않으면 내부 그룹으로 복사될 때 내부가 됩니다. 이 경우 그룹과 프로젝트가 비공개가 됩니다.
  - 비공개 그룹으로 복사될 때 비공개가 됩니다.

소스 인스턴스에서 개인 네트워크를 사용하여 일반 대중으로부터 콘텐츠를 숨긴 경우 목적지 인스턴스에서 유사한 설정이 있는지 확인하거나 비공개 그룹으로 가져오세요.

## 직접 전송 마이그레이션 프로세스 {#migration-by-direct-transfer-process}

[직접 전송을 사용하여 그룹 및 프로젝트 마이그레이션](direct_transfer_migrations.md)을 참조하세요.
