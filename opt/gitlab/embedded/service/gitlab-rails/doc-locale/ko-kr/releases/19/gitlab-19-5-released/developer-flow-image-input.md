---
title: "IDE에서 Developer 플로우 및 Agentic Chat의 컨텍스트로 이미지 제공"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/project/merge_requests/developer/#provide-images-as-context"
work_item: https://gitlab.com/groups/gitlab-org/modelops/applied-ml/code-suggestions/-/work_items/61
categories: [ Duo Developer ]
level: secondary
weight: 50
---

이전 버전의 GitLab에서는 Developer 플로우와 Agentic Chat이 텍스트만 읽을 수 있어서 버그 보고서의 스크린샷이나 디자인 논의의 다이어그램이 모델에 도달하지 못했습니다. 이제 Agentic Chat에서 시작하는 경우를 포함하여 Developer 플로우와 IDE의 Agentic Chat이 리포지토리의 이미지와 같은 프로젝트의 이슈, 머지 리퀘스트 및 댓글의 첨부 파일을 읽고 이를 컨텍스트로 사용할 수 있습니다.

프롬프트에 이미지를 직접 업로드할 수 없습니다. 대신 리포지토리의 파일 경로나 업로드 참조로 기존 이미지의 이름을 지정합니다. 자세한 내용은 문서를 참조하세요.
