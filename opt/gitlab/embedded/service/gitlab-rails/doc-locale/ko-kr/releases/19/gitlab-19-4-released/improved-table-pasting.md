---
title: 리치 텍스트 편집기에서 개선된 표 붙여넣기
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: plan
documentation_link: "../../../user/rich_text_editor/#paste-into-a-table-cell"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/627112
categories: [ Text Editors ]
level: secondary
---

이전에는 복사한 표를 표 셀에 붙여넣을 때 항상 복사한 셀이 기존 표로 병합되어 중첩 표를 만들기가 어려웠습니다.

이제 붙여넣은 표의 동작 방식을 선택할 수 있습니다:

- **셀에 붙여넣기**를 선택하여 복사한 표를 셀 내부의 중첩 표로 삽입합니다.
- **표로 병합하여 붙여넣기**를 선택하여 복사한 셀을 기존 표에 배포합니다. 이는 기본 동작입니다.

표를 중첩 표로 셀에 붙여넣을 때 사용할 수 있는 키보드 단축키도 있습니다: macOS에서는 <kbd>Command</kbd>+<kbd>Option</kbd>+<kbd>V</kbd>, Windows 및 Linux에서는 <kbd>Control</kbd>+<kbd>Alt</kbd>+<kbd>V</kbd>입니다.

<kbd>Control</kbd>+<kbd>V</kbd> 또는 <kbd>Command</kbd>+<kbd>V</kbd>를 사용한 표준 붙여넣기는 이전과 동일하게 작동합니다.
