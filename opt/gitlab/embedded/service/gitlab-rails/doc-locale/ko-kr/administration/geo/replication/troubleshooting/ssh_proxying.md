---
stage: GitLab Dedicated
group: Geo
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Geo SSH 응답 코드 오류 문제 해결
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

## NGINX Ingress를 사용하는 Cloud Native 배포에서 SSH pull 및 push가 무한정 중단됨 {#ssh-pull-and-push-hang-indefinitely-on-cloud-native-deployments-using-nginx-ingress}

> [!note]
> 이 문제는 번들 NGINX Ingress를 사용하는 Cloud Native GitLab 배포에만 영향을 미칩니다. Envoy를 Ingress 컨트롤러로 사용하는 배포는 이 문제의 영향을 받지 않습니다.

Helm Chart를 사용하여 배포된 보조 사이트에서 SSH push 및 pull은 다음 기능 플래그가 활성화되면 무한정 중단될 수 있습니다:

- `geo_proxy_fetch_ssh_to_primary`
- `geo_proxy_push_ssh_to_primary`

이 플래그는 Geo 보조에 대해 시작된 Git 작업의 SSH 프록시 경로를 변경합니다. 이들은 GitLab 버전 19.4.0 이상에서 기본적으로 활성화되었습니다.

이 문제는 webservice Ingress의 NGINX 요청 버퍼링으로 인해 발생합니다. GitLab Shell은 Git 클라이언트가 ref 광고를 기다리는 동안 스트리밍 요청 본문을 전송합니다. NGINX는 요청 본문을 기다리고 Git 클라이언트는 응답을 기다리므로 요청이 Workhorse에 도달하지 않습니다.

이를 해결하려면 배포에 맞는 옵션을 선택하세요:

- GitLab 18.11 이상: 두 기능 플래그를 모두 비활성화합니다:
  - `geo_proxy_fetch_ssh_to_primary`
  - `geo_proxy_push_ssh_to_primary`
- GitLab 19.0 이상:
  - [Envoy Gateway](https://docs.gitlab.com/charts/installation/migration/envoy_gateway_migration/)를 Ingress 컨트롤러로 사용하도록 업그레이드합니다.

번들 NGINX Ingress를 사용하는 동안 두 기능 플래그를 모두 활성화한 상태로 두지 마세요. 사용자가 Geo 보조를 통해 SSH fetch 또는 push를 완료하지 못할 수 있습니다.

기술 세부 정보는 [Geo 프록시 Git fetch 오류: 치명적 오류: 원격 끝이 예기치 않게 종료됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/454707)을 참조하세요.

## 오류: `Net::ReadTimeout` Geo 보조에서 SSH를 통해 push할 때 {#error-netreadtimeout-when-pushing-through-ssh-on-a-geo-secondary}

Geo 보조 사이트에서 SSH를 통해 대규모 리포지토리를 push할 때 시간 초과가 발생할 수 있습니다. 이는 Rails가 push를 기본에 프록시하고 60초의 기본 시간 초과를 갖기 때문이며, [이 Geo 이슈에 설명되어 있습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/7405). 이 문제는 `geo_proxy_push_ssh_to_primary` 기능 플래그가 비활성화되었을 때만 발생합니다.

현재 해결 방법은 다음과 같습니다:

- HTTP를 통해 push합니다. 여기서 Workhorse는 요청을 기본에 프록시하거나 (Geo 프록싱이 활성화되지 않은 경우 기본으로 리다이렉트합니다).
- 기본에 직접 push합니다.

예제 로그 (`gitlab-shell.log`):

```plaintext
Failed to contact primary https://primary.domain.com/namespace/push_test.git\\nError: Net::ReadTimeout\",\"result\":null}" code=500 method=POST pid=5483 url="http://127.0.0.1:3000/api/v4/geo/proxy_git_push_ssh/push"
```
