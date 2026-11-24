---
title: "설정 파일을 사용하여 GitLab Duo CLI 구성"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/settings/"
work_item: https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2126
categories: [ Duo CLI ]
level: secondary
weight: 50
---

이제 GitLab Duo CLI를 설정 파일로 구성할 수 있습니다. 개인 또는 전체 조직용으로 구성할 수 있습니다.

설정 파일은 `/settings` 패널에서 선택한 사항을 저장합니다. 파일을 직접 편집하거나 미리 생성할 수도 있습니다. 예를 들어 컨테이너 이미지에서 생성할 수 있습니다.

시스템 관리자는 모바일 디바이스 관리 도구 또는 그룹 정책을 사용하여 각 머신에 관리되는 설정 파일을 배포할 수 있습니다. 관리되는 파일의 설정은 설정 파일, 명령줄 옵션 및 환경 변수보다 우선하며 사용자는 이를 변경할 수 없습니다. 관리되는 파일에 없는 설정은 사용자 제어 상태로 유지됩니다.

설정 파일은 GitLab Duo CLI 9.26.0 이상이 필요하며, 관리되는 설정 파일은 GitLab Duo CLI 9.27.0 이상이 필요합니다.
