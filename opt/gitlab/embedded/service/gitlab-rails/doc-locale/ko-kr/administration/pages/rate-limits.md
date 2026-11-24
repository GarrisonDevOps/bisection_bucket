---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Pages 속도 제한
description: GitLab Pages 요청 및 TLS 연결에 대한 속도 제한을 IP 주소 또는 도메인으로 구성합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 17.3에서 [변경됨](https://gitlab.com/groups/gitlab-org/-/work_items/14653): Pages 속도 제한에서 서브넷을 제외할 수 있습니다.

{{< /history >}}

속도 제한을 적용하여 서비스 거부(DoS) 공격의 위험을 최소화할 수 있습니다. GitLab Pages는 토큰 버킷 알고리즘을 사용하여 속도 제한을 적용합니다. 기본적으로 지정된 제한을 초과하는 요청 또는 TLS 연결은 보고되고 거부됩니다.

GitLab Pages는 다음과 같은 유형의 속도 제한을 지원합니다:

- 각 `source_ip`에 대해: 단일 클라이언트 IP 주소의 요청 또는 TLS 연결을 제한합니다.
- 각 `domain`에 대해: GitLab Pages에 호스팅된 도메인당 요청 또는 TLS 연결을 제한합니다. `example.com`와 같은 사용자 지정 도메인이거나 `group.gitlab.io`과 같은 그룹 도메인일 수 있습니다.

HTTP 요청 기반 속도 제한은 다음 설정을 사용하여 적용됩니다:

- `rate_limit_source_ip`: 클라이언트 IP당 초당 최대 요청 수입니다. `0`로 설정하여 비활성화합니다.
- `rate_limit_source_ip_burst`: 클라이언트 IP당 초기 버스트에서 허용되는 최대 요청 수입니다(예: 페이지가 여러 리소스를 동시에 로드할 때).
- `rate_limit_domain`: 호스팅된 Pages 도메인당 초당 최대 요청 수입니다. `0`로 설정하여 비활성화합니다.
- `rate_limit_domain_burst`: 호스팅된 Pages 도메인당 초기 버스트에서 허용되는 최대 요청 수입니다.

TLS 연결 기반 속도 제한은 다음 설정을 사용하여 적용됩니다:

- `rate_limit_tls_source_ip`: 클라이언트 IP당 초당 최대 TLS 연결 수입니다. `0`로 설정하여 비활성화합니다.
- `rate_limit_tls_source_ip_burst`: 클라이언트 IP당 초기 버스트에서 허용되는 최대 TLS 연결 수입니다.
- `rate_limit_tls_domain`: 호스팅된 Pages 도메인당 초당 최대 TLS 연결 수입니다. `0`로 설정하여 비활성화합니다.
- `rate_limit_tls_domain_burst`: 호스팅된 Pages 도메인당 초기 버스트에서 허용되는 최대 TLS 연결 수입니다.

특정 IP 범위(서브넷)가 모든 속도 제한을 우회하도록 허용하려면 `rate_limit_subnets_allow_list`을(를) 사용합니다. 예를 들어, `['1.2.3.4/24', '2001:db8::1/32']`입니다. [GitLab Pages 차트 예제](https://docs.gitlab.com/charts/charts/gitlab/gitlab-pages/#configure-rate-limits-subnets-allow-list)를 사용할 수 있습니다.

클라이언트의 IP 주소가 IPv6인 경우, 전체 주소가 아닌 길이가 64인 IPv6 접두사에 제한이 적용됩니다.

## 소스 IP별 HTTP 요청 속도 제한 활성화 {#enable-http-requests-rate-limits-by-source-ip}

`/etc/gitlab/gitlab.rb`에서 속도 제한을 설정하려면:

1. 다음을 추가합니다:

   ```ruby
   gitlab_pages['rate_limit_source_ip'] = 20.0
   gitlab_pages['rate_limit_source_ip_burst'] = 600
   ```

1. 파일을 저장하고 [GitLab 재구성](../restart_gitlab.md#reconfigure-a-linux-package-installation)하여 변경 사항을 적용합니다.

## 도메인별 HTTP 요청 속도 제한 활성화 {#enable-http-requests-rate-limits-by-domain}

`/etc/gitlab/gitlab.rb`에서 속도 제한을 설정하려면:

1. 추가합니다:

   ```ruby
   gitlab_pages['rate_limit_domain'] = 1000
   gitlab_pages['rate_limit_domain_burst'] = 5000
   ```

1. 파일을 저장하고 [GitLab 재구성](../restart_gitlab.md#reconfigure-a-linux-package-installation)하여 변경 사항을 적용합니다.

## 소스 IP별 TLS 연결 속도 제한 활성화 {#enable-tls-connections-rate-limits-by-source-ip}

`/etc/gitlab/gitlab.rb`에서 속도 제한을 설정하려면:

1. 추가합니다:

   ```ruby
   gitlab_pages['rate_limit_tls_source_ip'] = 20.0
   gitlab_pages['rate_limit_tls_source_ip_burst'] = 600
   ```

1. 파일을 저장하고 [GitLab 재구성](../restart_gitlab.md#reconfigure-a-linux-package-installation)하여 변경 사항을 적용합니다.

## 도메인별 TLS 연결 속도 제한 활성화 {#enable-tls-connections-rate-limits-by-domain}

`/etc/gitlab/gitlab.rb`에서 속도 제한을 설정하려면:

1. 추가합니다:

   ```ruby
   gitlab_pages['rate_limit_tls_domain'] = 1000
   gitlab_pages['rate_limit_tls_domain_burst'] = 5000
   ```

1. 파일을 저장하고 [GitLab 재구성](../restart_gitlab.md#reconfigure-a-linux-package-installation)하여 변경 사항을 적용합니다.

## 관련 항목 {#related-topics}

- [GitLab Pages 관리](_index.md)
- [속도 제한](../../rate_limits/_index.md)
