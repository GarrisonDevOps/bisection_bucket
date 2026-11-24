---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 반복된 인증 실패 요청 후 클라이언트를 차단하는 금지.
title: 남용 및 인증 실패 금지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

일부 보호 메커니즘은 요청 속도를 저하시키는 대신 클라이언트를 일정 기간 동안 차단합니다.

## Git 및 컨테이너 레지스트리에 대한 인증 실패 금지 {#failed-authentication-ban-for-git-and-container-registry}

기본적으로 GitLab은 단일 IP 주소에서 1분 내에 10번의 인증 실패 요청이 수신되면 1시간 동안 HTTP 상태 코드 `403`을 반환합니다. 이 세 값은 모두 구성 가능합니다. 이는 다음의 조합에만 적용됩니다:

- Git 요청.
- 컨테이너 레지스트리(`/jwt/auth`) 요청.

이 제한:

- 금지가 시작될 때까지 성공적으로 인증하는 요청으로 재설정됩니다. 예를 들어, 9번의 인증 실패 요청 다음에 1번의 성공한 요청, 그 다음에 9번 더 많은 인증 실패 요청이 발생해도 금지가 트리거되지 않습니다.
- 금지가 시작되면 인증으로 삭제할 수 없습니다. 금지는 자격 증명 이전에 확인되므로, 금지된 IP는 금지가 만료될 때까지 유효한 자격 증명이 있어도 `403`을 받습니다.
- `gitlab-ci-token`으로 인증된 JWT 요청에는 적용되지 않습니다.
- 기본적으로 비활성화됩니다.

응답 헤더가 제공되지 않습니다.

속도 제한이 되지 않도록 다음을 수행할 수 있습니다:

- 자동화된 파이프라인의 실행을 분산시킵니다.
- 인증 실패 시도를 위해 [지수 백오프 및 재시도](https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/retry-backoff.html)를 구성합니다.
- 토큰 만료를 관리하기 위해 문서화된 프로세스 및 [모범 사례](https://about.gitlab.com/blog/access-token-lifetime-limits/#how-to-minimize-the-impact)를 사용합니다.

구성 정보는 [Linux 패키지 구성 옵션](https://docs.gitlab.com/omnibus/settings/configuration/#configure-a-failed-authentication-ban)을 참조하세요.

## 문제 해결 {#troubleshooting}

### Rack Attack이 로드 밸런서를 거부 목록에 추가함 {#rack-attack-is-denylisting-the-load-balancer}

모든 트래픽이 로드 밸런서에서 오는 것으로 보이면 Rack Attack이 로드 밸런서를 차단할 수 있습니다. 이 경우 다음을 수행해야 합니다:

1. [`nginx[real_ip_trusted_addresses]`을 구성합니다](https://docs.gitlab.com/omnibus/settings/nginx/#configure-gitlab-trusted-proxies-and-nginx-real_ip-module). 이는 사용자 IP가 로드 밸런서 IP로 나열되는 것을 방지합니다.
1. 로드 밸런서의 IP 주소를 허용 목록에 추가합니다.
1. GitLab을 재구성합니다.

   ```shell
   sudo gitlab-ctl reconfigure
   ```

### Rack Attack에서 차단된 IP를 Redis로 제거 {#remove-blocked-ips-from-rack-attack-with-redis}

차단된 IP를 제거하려면:

1. 프로덕션 로그에서 차단된 IP를 찾습니다:

   ```shell
   grep "Rack_Attack" /var/log/gitlab/gitlab-rails/auth.log
   ```

1. 거부 목록은 속도 제한 Redis 인스턴스에 저장되므로 `redis-cli`을(를) 열어야 합니다. 인스턴스를 분리하지 않는 설치에서는 다음이 기본 Redis입니다:

   ```shell
   /opt/gitlab/embedded/bin/redis-cli -s /var/opt/gitlab/redis/redis.socket
   ```

   `gitlab_rails['redis_rate_limiting_instance']`을(를) 구성한 경우 대신 해당 인스턴스에 연결합니다. 잘못된 인스턴스에서 키를 삭제하면 성공한 것으로 나타나지만 금지가 유지됩니다.

1. 다음 구문을 사용하여 블록을 제거할 수 있으며, `<ip>`을(를) 거부 목록에 있는 실제 IP로 바꿉니다:

   ```plaintext
   del cache:gitlab:rack::attack:allow2ban:ban:<ip>
   ```

1. IP가 포함된 키가 더 이상 표시되지 않음을 확인합니다:

   ```plaintext
   keys *rack::attack*
   ```

   기본적으로 [`keys` 명령이 비활성화됩니다](https://docs.gitlab.com/omnibus/settings/redis/#renamed-commands).

1. 선택적으로 [IP를 허용 목록에 추가](https://docs.gitlab.com/omnibus/settings/configuration/#configure-a-failed-authentication-ban)하여 다시 거부 목록에 추가되는 것을 방지합니다.
