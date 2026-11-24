---
title: 머지 리퀘스트 생성 이벤트 트리거
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
documentation_link: "../../../user/duo_agent_platform/triggers/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22279
categories: [ DAP Triggers ]
level: secondary
weight: 50
---

이전 버전의 GitLab에서 **머지 리퀘스트** 트리거 이벤트 타입은 **승인됨**, **준비됨으로 마킹**, **머지 충돌** 작업만 지원했습니다. GitLab 외부의 도구를 사용하지 않고는 누군가 머지 리퀘스트를 열 때 플로우나 외부 에이전트를 실행할 방법이 없었습니다.

이제 **생성됨**을 트리거 작업으로 선택할 수 있습니다. 누군가 머지 리퀘스트를 초안이나 준비 상태로 열 때, GitLab이 diff를 생성하면 플로우나 외부 에이전트가 실행됩니다. 1차 검토에 사용하거나 관련 이슈의 컨텍스트를 추가하려면 이를 사용합니다.

이 트리거를 구성하려면 프로젝트의 **AI > 트리거**로 이동하거나 플로우를 활성화할 때 선택합니다.
