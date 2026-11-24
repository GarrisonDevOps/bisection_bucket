---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments
title: GitLab Duo Agent Platform 인증
---

GitLab Duo Agent Platform은 요청이 모델 제공자에게 도달하기 전에 다중 토큰 인증 체인을 사용합니다.

다음 표는 각 토큰의 토큰 유형과 수명(TTL)을 나열합니다.

| 토큰  | 발급자 | TTL    | 새로 고침 동작                                        |
|--------|--------|--------|---------------------------------------------------------|
| Cloud Connector JWT(자체 서명) | GitLab Dedicated 인스턴스 | 1시간  | 각 요청에서 |
| CustomersDot 서비스 액세스 토큰 | `customers.gitlab.com`    | 약 3일 | 2일 미만이 남았을 때 시간마다 cron에서 |
| OAuth 액세스 토큰                | GitLab Dedicated 인스턴스 | 2시간  | 각 워크플로우에서                                 |
| GitLab Duo Workflow Service 내부 JWT           | GitLab Duo Workflow Service | 1시간 | 각 워크플로우에서 `GenerateToken` RPC를 사용합니다. |
| GLGO exchange JWT                 | AI Gateway                | 1시간                              |  각 요청에서 |
