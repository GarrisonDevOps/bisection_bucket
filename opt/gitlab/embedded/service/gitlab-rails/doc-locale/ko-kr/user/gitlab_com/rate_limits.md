---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab.com에 적용되는 속도 제한에 대해 알아보고, 각 구독 플랜별 제안된 제한사항을 확인합니다."
title: GitLab.com 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

GitLab.com에는 다음과 같은 속도 제한이 적용됩니다.

GitLab Self-Managed와 GitLab Dedicated 인스턴스는 자체 제한사항이 있으며, 인스턴스 운영자가 이를 제어합니다. GitLab.com을 사용하지 않는 경우 대신 [속도 제한](../../rate_limits/_index.md) 또는 [인증된 사용자 속도 제한](../../administration/dedicated/user_rate_limits.md)을 참조합니다.

## 플랜별 속도 제한 {#rate-limits-by-plan}

> [!note]
> 이 섹션의 제한사항은 제안 단계이며 아직 시행 중이 아닙니다. [현재 속도 제한](#current-rate-limits)은 현재 적용되며, 이러한 변경사항이 시행된 후에도 계속 적용됩니다. GitLab은 특정 날짜를 미리 공지합니다. 제한이 시행되기 전에 GitLab은 예정된 중단 기간을 운영하며, 이때 새 제한이 잠시 활성화되어 새 제한이 워크로드에 어떻게 영향을 미치는지 확인할 수 있습니다.

속도 제한이 티어 인식 기능으로 변경되고 있습니다. 모든 사용자에게 동일한 숫자 대신, 제한사항이 플랜을 반영하며 각 사용자에게 적용됩니다. 인증된 요청은 플랜의 전체 허용치를 받습니다. 익명 요청은 유사한 플랫폼과 일치하는 훨씬 더 낮은 허용치를 받습니다.

각 플랜에는 인증된 트래픽에 대한 두 가지 제한사항이 있으며, 지속 제한이 우선합니다:

- 지속 제한 (매시간 측정). 이 숫자를 사용하여 사용량을 계획합니다.
- 버스트 제한 (매분 측정). GitLab은 짧은 급증이 전체 시간 허용치를 한 번에 사용하지 않도록 이 기본값을 설정합니다.

정상적인 작업의 경우 먼저 지속 제한에 도달합니다. 버스트 제한에서 전체 시간 동안 요청을 전송하면 모든 플랜에서 지속 제한을 초과합니다. 버스트 제한을 짧은 급증의 상한선으로 취급하며, 유지할 수 있는 속도가 아닙니다.

버스트 제한의 요청은 Free에서 약 50분, Premium에서 12분, Ultimate에서 12.5분 내에 지속 제한에 도달합니다.

이러한 제한사항은 API 요청, 웹 요청, HTTPS를 통한 인증된 Git 요청에 적용됩니다. HTTPS를 통한 인증되지 않은 Git 요청은 인증되지 않은 제한에 포함되지 않습니다. 이들은 [IP 주소의 현재 제한](#current-rate-limits)에 따릅니다.

### 지속 제한 {#sustained-limits}

| 속도 제한                                 | Free            | Premium          | Ultimate         |
| ------------------------------------------ | --------------- | ---------------- | ---------------- |
| 사용자의 인증된 트래픽           | 시간당 5,000개 | 시간당 15,000개 | 시간당 25,000개 |
| IP 주소의 인증되지 않은 트래픽 | 시간당 60개    | 시간당 60개     | 시간당 60개     |

### 버스트 제한 {#burst-limits}

| 속도 제한                       | Free            | Premium           | Ultimate          |
| -------------------------------- | --------------- | ----------------- | ----------------- |
| 사용자의 인증된 트래픽 | 분당 100개 | 분당 1,250개 | 분당 2,000개 |

## 제한을 초과할 때 {#when-you-exceed-a-limit}

요청이 속도 제한되면 GitLab은 `429 Too Many Requests` 상태 코드로 응답합니다. 요청을 다시 시도하기 전에 기다립니다.

제한된 요청에 대한 응답에는 할당량이 재설정될 때까지 남은 시간(초)을 나타내는 `Retry-After` 헤더와 동일한 정보를 날짜 및 시간으로 나타내는 `RateLimit-ResetTime` 헤더가 포함됩니다. 제한되었는지 여부에 관계없이 모든 응답에는 `RateLimit-Limit`, `RateLimit-Remaining`, 제한에 도달하기 전에 사용량을 추적하는 데 사용할 수 있는 관련 헤더가 포함됩니다. 전체 목록은 [응답 헤더](../../administration/settings/user_and_ip_rate_limits.md#response-headers)를 참조합니다.

제한을 올바르게 처리하려면:

- 다시 시도하기 전에 `Retry-After`에 주어진 시간만큼 기다립니다.
- 계속 제한되면 기하급수적으로 백오프합니다.
- `RateLimit-Remaining`을 모니터링하고 할당량을 소진하기 전에 속도를 늦춥니다.

Projects, Groups, Users API에 대한 속도 제한 응답은 정보 제공 헤더를 포함하지 않습니다. 응답 헤더는 다른 일부 제한을 반영하지 않으므로, 이전 응답의 헤더에 남은 할당량이 표시되었을 때도 `429` 응답을 받을 수 있습니다.

## 더 많은 여유가 필요한 경우 {#if-you-need-more-headroom}

제한에 정기적으로 도달하면 최소 커밋부터 최대 커밋까지 여러 옵션이 있습니다:

1. API 사용을 최적화합니다. 요청을 배치하고, 응답을 캐시하고, 페이지 매김을 사용하고, `Retry-After` 헤더를 준수합니다. 대부분의 사용량은 제한 이하로 유지됩니다.
1. 요청을 인증합니다. 익명 트래픽은 가장 낮은 허용치를 받습니다. [개인 액세스 토큰, OAuth 토큰, CI/CD 작업 토큰](../../api/rest/authentication.md)으로 인증하면 플랜의 전체 제한을 받습니다.
1. 플랜을 업그레이드합니다. Premium과 Ultimate는 더 높은 제한을 가집니다.

플랜의 제한을 초과하는 지속적인 요구사항의 경우, 추가 여유를 구매하는 옵션이 설계 중입니다. 자세한 사항은 가용성에 가까워질수록 공개됩니다.

## 현재 속도 제한 {#current-rate-limits}

이러한 제한사항은 오늘 GitLab.com에서 시행 중이며, [플랜별 속도 제한](#rate-limits-by-plan)이 도입된 후에도 계속 적용됩니다.

GitLab은 먼저 플랜의 제한을 확인한 다음 이 표의 제한을 확인합니다. 낮은 제한이 적용됩니다. 이 표의 제한이 플랜의 제한보다 낮을 수 있으므로, 먼저 해당 제한에 도달할 수 있습니다.

예를 들어, 사용자의 인증된 API 트래픽은 분당 2,000개 요청으로 제한됩니다. Free와 Premium에서는 플랜의 버스트 제한이 더 낮으므로 먼저 해당 제한에 도달합니다. Ultimate에서는 버스트 제한도 분당 2,000개 요청이므로 두 제한이 동일합니다.

| 속도 제한                                                                                                    | 설정                         |
| ------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| IP 주소의 보호된 경로                                                                             | 분당 10개 요청         |
| IP 주소에 대한 로그인 시도 (`POST /users/sign_in`)                                                    | 5분마다 10개 요청     |
| 프로젝트, 커밋 또는 파일 경로의 원본 엔드포인트 트래픽                                                      | 분당 300개 요청        |
| 프로젝트의 인증되지 않은 원본 엔드포인트 트래픽                                                            | 분당 800개 요청        |
| IP 주소의 인증되지 않은 트래픽                                                                    | 분당 500개 요청        |
| 사용자의 인증된 API 트래픽                                                                          | 분당 2,000개 요청      |
| 사용자의 인증된 비 API HTTP 트래픽                                                                 | 분당 1,000개 요청      |
| 사용자의 인증된 Git HTTPS 트래픽                                                                    | 분당 10,000개 요청     |
| IP 주소의 인증되지 않은 Git HTTPS 트래픽                                                          | 분당 15,000개 요청     |
| 사용자, 프로젝트 및 Git 명령의 Git SSH 작업                                                       | 분당 600개 작업      |
| IP 주소의 모든 트래픽                                                                                | 분당 2,000개 요청      |
| 이슈 생성                                                                                                | 분당 200개 요청        |
| 이슈 및 머지 리퀘스트의 노트 생성                                                                    | 분당 60개 요청         |
| IP 주소의 고급, 프로젝트 또는 그룹 검색 API                                                      | 분당 100개 요청        |
| 사용자의 고급, 프로젝트 또는 그룹 검색 API                                                             | 분당 100개 요청        |
| IP 주소의 GitLab Pages 요청                                                                       | 50초마다 1,000개 요청 |
| GitLab Pages 도메인의 GitLab Pages 요청                                                               | 10초마다 5,000개 요청 |
| IP 주소의 GitLab Pages TLS 연결                                                                | 50초마다 1,000개 요청 |
| GitLab Pages 도메인의 GitLab Pages TLS 연결                                                        | 10초마다 400개 요청   |
| 프로젝트, 사용자 또는 커밋의 파이프라인 생성 요청                                                     | 분당 25개 요청         |
| 사용자의 파이프라인 생성 요청                                                                         | 분당 2,000개 요청      |
| 프로젝트의 경고 통합 엔드포인트 요청                                                             | 시간당 3,600개 요청       |
| GitLab Duo `aiAction` 요청                                                                                | 8시간마다 160개 요청      |
| [끌어오기 미러링](../project/repository/mirror/pull.md) 간격                                              | 5분                       |
| 사용자로부터 `/api/v4/users/:id`에 대한 API 요청                                                               | 10분마다 300개 요청   |
| IP 주소의 GitLab 패키지 호스팅 시스템 요청                                                      | 분당 1,000개 요청      |
| IP 주소 및 파일 경로의 리포지토리 파일 API 요청 (`GET /api/v4/projects/:id/repository/files/*`) | 분당 500개 요청        |
| 사용자 팔로워 요청 (`/api/v4/users/:id/followers`)                                                       | 분당 100개 요청        |
| 사용자 팔로잉 요청 (`/api/v4/users/:id/following`)                                                       | 분당 100개 요청        |
| 사용자 상태 요청 (`/api/v4/users/:user_id/status`)                                                        | 분당 240개 요청        |
| 사용자 SSH 키 요청 (`/api/v4/users/:user_id/keys`)                                                        | 분당 120개 요청        |
| 단일 SSH 키 요청 (`/api/v4/users/:id/keys/:key_id`)                                                    | 분당 120개 요청        |
| 사용자 GPG 키 요청 (`/api/v4/users/:id/gpg_keys`)                                                         | 분당 120개 요청        |
| 단일 GPG 키 요청 (`/api/v4/users/:id/gpg_keys/:key_id`)                                                | 분당 120개 요청        |
| 사용자 프로젝트 요청 (`/api/v4/users/:user_id/projects`)                                                    | 분당 300개 요청        |
| 사용자가 기여한 프로젝트 요청 (`/api/v4/users/:user_id/contributed_projects`)                            | 분당 100개 요청        |
| 사용자 즐겨찾기 프로젝트 요청 (`/api/v4/users/:user_id/starred_projects`)                                    | 분당 100개 요청        |
| 프로젝트 목록 요청 (`/api/v4/projects`)                                                                   | 10분마다 2,000개 요청 |
| IP 주소의 인증되지 않은 프로젝트 목록 요청 (`/api/v4/projects`)                                | 10분마다 400개 요청   |
| 그룹 프로젝트 요청 (`/api/v4/groups/:id/projects`)                                                       | 분당 600개 요청        |
| 단일 프로젝트 요청 (`/api/v4/projects/:id`)                                                              | 분당 400개 요청        |
| 그룹 목록 요청 (`/api/v4/groups`)                                                                       | 분당 50개 요청         |
| 단일 그룹 요청 (`/api/v4/groups/:id`)                                                                  | 분당 400개 요청        |
| 러너 토큰을 사용한 러너 작업 요청 (`/api/v4/jobs/request`)                                            | 분당 2,000개 요청      |
| IP 주소의 러너 토큰을 사용한 러너 작업 요청 (`/api/v4/jobs/request`)                         | 분당 2,400개 요청      |
| 작업 토큰을 사용한 러너 작업 트레이스 패치 요청 (`/api/v4/jobs/trace`)                                      | 분당 200개 요청        |
| 작업 토큰을 사용한 러너 작업 요청 (`/api/v4/jobs/*`)                                                     | 분당 200개 요청        |
| 프로젝트의 모든 프로젝트 멤버 나열                                                                         | 분당 200개 요청        |

[보호된 경로](#protected-paths-throttle) 및 [원본 엔드포인트](../../administration/settings/rate_limits_on_raw_endpoints.md)의 속도 제한에 대해 자세히 알아봅니다.

GitLab은 여러 계층에서 요청을 속도 제한할 수 있습니다. 이러한 제한은 각 IP 주소에 대해 가장 제한적입니다.

## Service Desk 이메일 속도 제한 {#service-desk-email-rate-limit}

GitLab.com은 최상위 그룹이 시간당 및 일일로 보낼 수 있는 아웃바운드 Service Desk 알림 이메일 수를 플랜별로 제한합니다:

| 플랜                                   | 시간당 제한 | 일일 제한 |
| -------------------------------------- | ------------ | ----------- |
| Free, Premium 평가판, Ultimate 평가판    | 100          | 700         |
| 오픈 소스                            | 1,500        | 10,000      |
| Premium                                | 5,000        | 50,000      |
| Ultimate, Ultimate 평가판 유료 고객 | 무제한    | 무제한   |

자세한 내용은 [Service Desk 이메일 속도 제한](../../administration/instance_limits.md#service-desk-email-rate-limit)을 참조합니다.

## 내보내기 파일을 업로드하여 그룹 및 프로젝트 가져오기 {#group-and-project-import-by-uploading-export-files}

남용을 방지하기 위해 GitLab.com은 다음에 속도 제한을 적용합니다:

- 프로젝트 및 그룹 가져오기.
- 파일을 사용하는 그룹 및 프로젝트 내보내기.
- 내보내기 다운로드.

자세한 정보는 다음을 참조하세요.

- [프로젝트 가져오기/내보내기 속도 제한](../project/settings/import_export.md#rate-limits).
- [그룹 가져오기/내보내기 속도 제한](../project/settings/import_export.md#rate-limits-1).

## IP 차단 {#ip-blocks}

GitLab.com이 시스템이 잠재적으로 악의적이라고 판단하는 단일 IP 주소에서 비정상적인 트래픽을 받을 때 IP 차단이 발생할 수 있습니다. 이러한 차단은 속도 제한 설정을 기반으로 할 수 있습니다. 비정상적인 트래픽이 중단된 후 GitLab은 자동으로 IP 주소를 해제합니다. 해제 시간은 차단 유형에 따라 다르며, 다음 섹션에서 설명합니다.

GitLab.com에 대한 모든 요청에 대해 `403 Forbidden` 오류를 받으면, 차단을 트리거할 수 있는 자동화된 프로세스가 있는지 확인합니다. 지원을 받으려면 영향받은 IP 주소 등의 세부 정보와 함께 [GitLab 지원](https://support.gitlab.com)에 문의합니다.

### Git 및 컨테이너 레지스트리 실패한 인증 차단 {#git-and-container-registry-failed-authentication-ban}

단일 IP 주소가 1분 기간 내에 300개의 실패한 인증 요청을 전송할 때 GitLab.com은 15분 동안 `403 Forbidden` 상태 코드로 응답합니다.

이 응답은 Git 요청 및 컨테이너 레지스트리 (`/jwt/auth`) 요청(결합)에만 적용됩니다.

이 제한:

- 성공적으로 인증된 요청으로 재설정됩니다. 예를 들어, 299개의 실패한 인증 요청 다음에 성공한 요청, 그 다음에 299개의 실패한 인증 요청이 더 있어도 차단이 트리거되지 않습니다.
- `gitlab-ci-token`으로 인증된 JWT 요청에는 적용되지 않습니다.

응답 헤더가 제공되지 않습니다.

HTTPS를 통한 Git 요청은 항상 인증되지 않은 요청을 먼저 전송하며, 프라이빗 리포지토리의 경우 `401 Unauthorized` 오류가 발생합니다. 그런 다음 Git은 사용 가능한 경우 사용자 이름, 비밀번호 또는 액세스 토큰을 사용하여 인증된 요청을 시도합니다. 너무 많은 요청이 동시에 전송되면 이러한 요청이 임시 IP 차단으로 이어질 수 있습니다. 이 문제를 해결하려면 [SSH 키를 사용하여 GitLab과 통신](../ssh.md)합니다.

## 구성할 수 없는 제한 {#non-configurable-limits}

GitLab.com에서 사용되는 구성할 수 없는 속도 제한에 대한 자세한 내용은 [구성할 수 없는 제한](../../rate_limits/non_configurable.md)을 참조합니다.

## 페이지 매김 응답 헤더 {#pagination-response-headers}

성능상의 이유로 쿼리가 10,000개 이상의 레코드를 반환하면 [GitLab은 일부 헤더를 제외합니다](../../api/rest/_index.md#pagination-response-headers).

## 보호된 경로 제한 {#protected-paths-throttle}

동일한 IP 주소가 보호된 경로에 분당 10개 이상의 POST 요청을 전송하면 GitLab.com은 `429 Too Many Requests` 상태 코드를 반환합니다.

보호된 경로에는 사용자 생성, 사용자 확인, 사용자 로그인 및 비밀번호 재설정이 포함됩니다. 전체 목록은 [보호된 경로](../../administration/settings/protected_paths.md)를 참조합니다.

GitLab이 차단된 요청에 포함하는 헤더의 경우 [사용자 및 IP 속도 제한](../../administration/settings/user_and_ip_rate_limits.md#response-headers)을 참조합니다.

## SSH 최대 연결 수 {#ssh-maximum-number-of-connections}

GitLab.com은 [`MaxStartups` 설정](https://man.openbsd.org/sshd_config.5#MaxStartups)을 사용하여 동시 인증되지 않은 SSH 연결의 최대 수를 정의합니다. 허용되는 최대 연결 수보다 많은 연결이 동시에 발생하면 GitLab은 초과 연결을 삭제합니다. 그러면 사용자는 [`ssh_exchange_identification` 오류](../../topics/git/troubleshooting_git.md#ssh_exchange_identification-error)를 받습니다.

## 관련 항목 {#related-topics}

- [GitLab.com 설정](_index.md)
- [속도 제한](../../rate_limits/_index.md)
- [Git 작업의 속도 제한](../../rate_limits/git.md)
- [REST API 인증](../../api/rest/authentication.md)
