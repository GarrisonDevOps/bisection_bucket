---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 특정 GitLab API 엔드포인트에 대한 속도 제한을 구성합니다.
title: API 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

대부분의 API 요청은 [일반 사용자 및 IP 속도 제한](../../administration/settings/user_and_ip_rate_limits.md)을 카운트합니다. 일부 API의 경우 대신 별도의 속도 제한을 구성할 수 있습니다. API 속도 제한은 해당 API에 대한 요청의 일반 제한을 무시합니다. 일반 제한을 변경하지 않고 단일 API의 제한을 높이거나 낮출 수 있습니다. 다른 동작은 변경되지 않습니다.

이러한 제한을 구성하려면 **운영자** 영역으로 이동하고 **설정** > **네트워크**를 선택합니다.

## 사용 가능한 API 속도 제한 {#available-api-rate-limits}

| API | 설명 |
|:----|:------------|
| [감사 이벤트 API](../../administration/settings/rate-limit-on-audit-events-api.md) | 인스턴스, 그룹 또는 프로젝트 감사 이벤트를 검색하는 요청을 제한합니다. |
| [더 이상 사용되지 않는 엔드포인트](deprecated.md) | 교환 호환성을 손상시키지 않고 제거할 수 없지만 대체 항목이 있는 엔드포인트를 제한합니다. |
| [그룹 API](groups.md) | 그룹을 나열, 검색, 생성 및 보관하고 그룹 구성원을 나열 및 삭제하는 요청을 제한합니다. |
| [조직 API](organizations.md) | 조직을 생성하는 요청을 제한합니다. |
| [패키지 레지스트리](package-registry.md) | 다운스트림 프로젝트에서 종속성을 해결하기 위해 호출하는 Packages API에 대한 요청을 제한합니다. |
| [프로젝트 API](projects.md) | 프로젝트를 나열, 검색 및 생성하고 프로젝트 구성원을 나열 및 삭제하는 요청을 제한합니다. |
| [리포지토리 파일 API](repository-files.md) | 리포지토리에서 파일을 가져오기, 생성, 업데이트 및 삭제하는 요청을 제한합니다. |
| [사용자 API](users.md) | 사용자의 팔로워, 상태, SSH 키 및 GPG 키를 읽는 요청을 제한합니다. |

## 관련 항목 {#related-topics}

- [속도 제한](../_index.md)
- [구성 불가능한 속도 제한](../non_configurable.md)
- [REST API](../../api/rest/_index.md)
