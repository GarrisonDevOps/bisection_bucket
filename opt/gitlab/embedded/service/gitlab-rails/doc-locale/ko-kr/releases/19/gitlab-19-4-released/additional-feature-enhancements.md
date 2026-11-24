---
title: 추가 기능 개선
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: verify
co_create: true
documentation_link: "../../../api/job_artifacts/#download-job-artifacts-by-job-id"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252518
categories: [ Job Artifacts ]
level: secondary
---

이 릴리스의 다른 개선 사항은 다음과 같습니다:

- API에서 특정 보고서 아티팩트를 가져옵니다. 다운로드 가능한 유형으로 제한되며 아티팩트별 인증 확인으로 제어됩니다. 예를 들어 JUnit 파일의 경우 `GET /projects/:id/jobs/:job_id/artifacts?file_type=junit`를 사용합니다.
- 관리자는 클라이언트가 작업 아티팩트 및 패키지 다운로드를 위해 직접 302 리다이렉트와 프록시된 전송 중에서 선택하도록 할 수 있습니다.
- 파이프라인 편집기는 이제 백엔드에서 이미 지원하는 CI/CD 키워드를 검증합니다.
- 빈 제목 줄이 있는 이메일은 이제 반송되는 대신 Service Desk 티켓을 엽니다.
- `Dependency-Scanning.v2` 템플릿에서 두 개의 새로운 타임아웃 입력으로 종속성 해결 한도를 직접 높입니다.
- 관리자는 각 사용자가 이메일 링크를 수락하지 않아도 프로필에 표시되도록 성취를 설정할 수 있습니다.

이러한 기여를 해주신 다음 사용자들께 감사드립니다!

- [Andreas Kunze](https://gitlab.com/and2345) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252518))
- [André Düwel](https://gitlab.com/duewel1982) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/252350))
- [Paweł Farys](https://gitlab.com/vertisan) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250636))
- [Praveen Arimbrathodiyil](https://gitlab.com/pravi) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248600))
- [Niklas van Schrick](https://gitlab.com/Taucher2003) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249426))
- [BoxBoxJason](https://gitlab.com/BoxBoxJason) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249893))
