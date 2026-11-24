---
title: "새로운 두 가지 CI/CD 변수: 재시도 횟수 및 작업 태그"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
co_create: true
documentation_link: "../../../ci/variables/predefined_variables/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/?sort=created_date&state=merged&milestone_title=19.3&label_name%5B%5D=Community%20contribution&label_name%5B%5D=release%20post%20item&label_name%5B%5D=group%3A%3Apipeline%20authoring
categories: [ Pipeline Composition ]
level: secondary
---

파이프라인 스크립트는 이제 처음 실행 중인지 여부를 확인할 수 있습니다. `CI_JOB_RETRY_COUNT`은(는) 현재 작업이 재시도된 횟수를 나타내며 첫 실행 시 `0`이(가) 되므로 재시도 인식 로직은 더 이상 상태를 직접 추적할 필요가 없습니다. 별도로 `CI_JOB_TAGS`은(는) 작업의 구성된 태그를 노출하며, 이전에는 `CI_RUNNER_TAGS`을(를) 통해서만 러너의 태그가 표시되었습니다. 둘 다 설정 없이 사용할 수 있습니다.

이 기여를 해주신 [Giannis Kepas](https://gitlab.com/gkepas)님과 [Dwight Blake](https://gitlab.com/lunivilen)님에게 감사합니다!
