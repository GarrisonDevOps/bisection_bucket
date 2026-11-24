---
title: Geo SSH 프록시가 기본적으로 활성화됨
tier: [ Premium, Ultimate ]
offering: [ self_managed ]
stage: GitLab Dedicated
documentation_link: '../../../administration/geo/replication/troubleshooting/ssh_proxying'
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/454707"
categories: [ Geo Replication ]
---

Geo SSH 프록시가 기본적으로 활성화됨

다음 기능 플래그는 GitLab 19.4에서 기본적으로 활성화됩니다:

- `geo_proxy_fetch_ssh_to_primary`
- `geo_proxy_push_ssh_to_primary`

Geo SSH 프록시는 작업이 주 사이트로 프록시될 때 Geo 보조 사이트로의 SSH 가져오기 및 푸시를 위한 더욱 안정적인 경로를 제공합니다. 또한 [푸시 옵션이 포함된 푸시](https://gitlab.com/gitlab-org/gitlab/-/issues/417186) 및 [대용량 리포지토리에서 가져오기](https://gitlab.com/gitlab-org/gitlab/-/issues/454707)와 같이 프록시된 작업이 실패한 오래된 버그를 해결합니다.

**Cloud Native GitLab 배포에 필요한 조치**

**번들로 제공되는 NGINX Ingress**를 사용하는 Cloud Native GitLab 배포는 다음 중 하나를 수행해야 합니다:

- 이 롤아웃 전에 [Gateway API with Envoy Gateway](https://docs.gitlab.com/charts/installation/migration/envoy_gateway_migration/)를 사용하도록 업그레이드하거나 **또는**
- 롤아웃 후 두 기능 플래그를 비활성화합니다.

그렇지 않으면 Geo 보조 사이트를 통한 SSH 가져오기 및 푸시가 중단되거나 시간이 초과될 수 있습니다.

자세한 내용은 [Geo 문제 해결 설명서](../../../administration/geo/replication/troubleshooting/ssh_proxying.md)에서 SSH 프록시를 참조하세요.
