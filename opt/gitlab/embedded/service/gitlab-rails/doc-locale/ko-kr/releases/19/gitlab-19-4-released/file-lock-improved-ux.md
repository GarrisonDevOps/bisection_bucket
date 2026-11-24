---
title: 파일 또는 디렉터리를 잠근 사용자 확인
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
documentation_link: "../../../user/project/file_lock"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/13019
categories: [ Source Code Management ]
level: secondary
weight: 50
---

파일이 잠겨 있으면 이제 누가 잠금했는지 그리고 어떤 옵션이 있는지 blob 뷰어를 떠나지 않고 확인할 수 있습니다.

이전에는 **잠김** 레이블만 나타났으며, 누가 파일을 잠금했는지 또는 직접 잠금을 해제할 수 있는지 알 수 있는 방법이 없었습니다. 이제 레이블 옆의 팝오버에 누가 잠금했는지 표시됩니다. 파일을 잠금 해제할 권한이 있으면 팝오버에 잠금 해제 작업이 포함됩니다. 없으면 이유를 설명합니다. 잠긴 디렉터리의 경우 팝오버가 변경 사항을 차단하는 특정 파일로 직접 연결합니다.
