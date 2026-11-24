---
title: 종속성 및 라이센스 스캐닝에서 SPDX 라이센스 표현식 지원
tier: [ Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: ../../../user/compliance/license_scanning_of_cyclonedx_files/
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/16801
categories: [ "Software Composition Analysis" ]
level: primary
---

GitLab 라이센스 데이터는 이제 `MIT OR Apache-2.0` 또는 `GPL-2.0-only WITH Classpath-exception-2.0`와 같은 복합 선언을 포함한 SPDX 라이센스 표현식을 제공합니다. 이전에는 종속성 목록에서 `unknown`로 보고되었으며 라이센스 승인 정책에서 볼 수 없었습니다.

복합 라이센스는 이제 종속성 목록에서 연산자(`AND`, `OR`, `WITH`)와 함께 표시되며, 라이센스 승인 정책은 단일 라이센스 종속성을 처리하는 것과 동일한 방식으로 이들을 허용하거나 거부할 수 있습니다.

CycloneDX SBOM에서 선언된 표현식은 GitLab 19.3 이후로 지원되었습니다. 이 릴리스는 이들을 GitLab이 동기화하는 라이센스 데이터에 추가합니다. 오프라인 인스턴스는 [v3 라이센스 데이터 다운로드](../../../topics/offline/quick_start_guide.md#download-v3-license-data) 후에만 표현식을 받습니다.
