---
title: GitLab Relay (KAS) 연결이 기본적으로 gRPC로 설정됩니다
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: verify
documentation_link: ../../../user/clusters/agent/install/
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23445
categories: [ GitLab Runner Core, Deployment Management ]
level: secondary
---

GitLab Relay (KAS)는 이제 기본적으로 gRPC를 사용합니다. GitLab.com은 GitLab 19.4에서 `grpcs://kas.gitlab.com`을 공지했습니다. GitLab 19.5에서 새로운 Linux 패키지 및 Helm 차트 설치 환경은 `grpcs://`도 공지합니다. 새 에이전트 설치는 WebSocket에 래핑된 gRPC 대신 `grpcs://`을 통해 연결되므로 라우팅 및 문제 해결을 위한 프로토콜이 하나이고 각 연결의 오버헤드가 감소합니다.

`wss://`을 통해 이미 연결된 에이전트는 작동하지만 이동해야 합니다. GitLab.com에서 에이전트 주소를 `grpcs://kas.gitlab.com`로 설정합니다. 예를 들어, `gitlab-agent` Helm 차트를 업그레이드할 때 `--set config.kasAddress=grpcs://kas.gitlab.com`을 사용합니다. GitLab Self-Managed에서는 업그레이드 후 [에이전트 설치 명령](../../../user/clusters/agent/install/_index.md)에 표시된 주소를 사용합니다.
