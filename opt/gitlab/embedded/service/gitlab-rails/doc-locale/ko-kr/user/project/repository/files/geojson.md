---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 프로젝트에서 GeoJSON 파일이 표시되는 방식.
title: GeoJSON 파일
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GeoJSON 파일은 JavaScript Object Notation(JSON)을 사용하여 지리적 데이터 구조를 인코딩하는 형식입니다. 점, 선, 다각형 등의 지리적 피처와 관련 속성을 표현하는 데 일반적으로 사용됩니다.

리포지토리에 추가되면 `.geojson` 확장자를 가진 파일은 GitLab에서 볼 때 GeoJSON 데이터가 포함된 지도로 렌더링됩니다.

지도 데이터는 [OpenStreetMap](https://www.openstreetmap.org/)에서 [Open Database License](https://www.openstreetmap.org/copyright)에 따라 제공됩니다.

![지도로 렌더링된 GeoJSON 파일](img/geo_json_file_rendered_v16_1.png)
