---
title: 보안 인벤토리의 집계된 스캐너 커버리지
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: security_risk_management
documentation_link: "../../../user/application_security/security_inventory/"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22124
categories: [ Security Asset Inventories ]
---

이제 한 페이지에서 전체 그룹 계층의 스캐너 커버리지를 볼 수 있습니다. GitLab의 이전 버전에서는 [보안 인벤토리](../../../user/application_security/security_inventory/_index.md)가 하위 그룹당 커버리지를 표시했지만 전체 그룹의 총계는 없었습니다. 이제 커버리지 위젯은 그룹 및 하위 그룹의 모든 프로젝트에서 스캐너 커버리지를 집계하고 각 스캐너가 활성화되어 있거나, 활성화되지 않았거나, 실패했거나, 부실한 프로젝트의 백분율과 수를 표시합니다. SAST 또는 종속성 검사와 같은 한 스캐너에 집중하려면 스캐너 드롭다운 목록을 사용합니다. 상태를 선택하여 프로젝트 목록을 필터링하고 포함되지 않은 프로젝트에 대한 스캐너를 켭니다.

보안 인벤토리는 이제 표시되는 열을 제어할 수 있습니다. **취약점**, **툴 커버리지**, **보안 속성** 열을 표시하거나 숨기려면 **표시**를 선택합니다.
