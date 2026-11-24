---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 릴리스 증거
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

릴리스가 생성될 때마다 GitLab은 이와 관련된 데이터의 스냅샷을 촬영합니다. 이 데이터는 JSON 파일로 저장되며 *릴리스 증거*라고 합니다. 이 기능에는 테스트 아티팩트, 연결된 마일스톤, 그리고 외부 감사와 같은 내부 프로세스를 용이하게 하기 위한 매칭 패키지가 포함됩니다.

릴리스 증거에 액세스하려면 릴리스 페이지에서 **증거 수집** 제목 아래에 나열된 JSON 파일 링크를 선택합니다.

또한 [API를 사용](../../../api/releases/_index.md#collect-release-evidence)하여 기존 릴리스에 대한 릴리스 증거를 생성할 수 있습니다. 따라서 각 릴리스에는 여러 릴리스 증거 스냅샷이 있을 수 있습니다. 릴리스 페이지에서 릴리스 증거 및 세부 정보를 볼 수 있습니다.

이슈 추적기가 비활성화되면 릴리스 증거를 [다운로드할 수 없습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/208397).

릴리스 증거 객체의 예를 다음에 나타냅니다:

```json
{
  "release": {
    "id": 5,
    "tag_name": "v4.0",
    "name": "New release",
    "project": {
      "id": 20,
      "name": "Project name",
      "created_at": "2019-04-14T11:12:13.940Z",
      "description": "Project description"
    },
    "created_at": "2019-06-28 13:23:40 UTC",
    "description": "Release description",
    "milestones": [
      {
        "id": 11,
        "title": "v4.0-rc1",
        "state": "closed",
        "due_date": "2019-05-12 12:00:00 UTC",
        "created_at": "2019-04-17 15:45:12 UTC",
        "description": "milestone description",
      },
      {
        "id": 12,
        "title": "v4.0-rc2",
        "state": "closed",
        "due_date": "2019-05-30 18:30:00 UTC",
        "created_at": "2019-04-17 15:45:12 UTC",
        "description": "milestone description",
      }
    ],
    "packages": [
      {
        "id": 1,
        "name": "my-package",
        "version": "4.0",
        "package_type": "generic",
        "created_at": "2019-06-20 10:00:00 UTC"
      }
    ],
    "report_artifacts": [
      {
        "url":"https://gitlab.example.com/root/project-name/-/jobs/111/artifacts/download"
      }
    ]
  }
}
```

## 릴리스 증거로 패키지 포함 {#include-packages-as-release-evidence}

{{< history >}}

- GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/283995)되었습니다.

{{< /history >}}

릴리스가 생성되면 GitLab은 자동으로 프로젝트의 [패키지 레지스트리](../../packages/package_registry/_index.md)에서 버전이 릴리스 태그와 일치하는 패키지를 쿼리합니다. 매칭 패키지는 `packages` 키 아래의 릴리스 증거 JSON에 포함됩니다.

버전 매칭은 다음과 같이 작동합니다:

- 릴리스 태그에 `v` 또는 `V` 접두사가 있는 경우(예: `v1.0.0`), 접두사는 매칭하기 전에 제거됩니다. 태그 `v1.0.0`는 버전 `1.0.0`인 패키지와 일치합니다.
- 릴리스 태그에 접두사가 없으면(예: `1.0.0`), 직접 매칭됩니다.
- [표시 가능한 패키지](../../packages/package_registry/_index.md)만 포함됩니다. 제거 대기 중이거나 오류 상태인 패키지는 제외됩니다.
- 여러 패키지가 단일 릴리스와 일치할 수 있습니다. 예를 들어 프로젝트에서 버전 `1.0.0`인 일반 패키지와 npm 패키지를 모두 게시하는 경우, 둘 다 증거에 포함됩니다.

증거의 각 패키지 항목에는 다음 필드가 포함됩니다:

| 필드          | 설명                                                    |
|----------------|----------------------------------------------------------------|
| `id`           | 패키지의 고유 ID입니다.                                  |
| `name`         | 패키지의 이름입니다.                                       |
| `version`      | 패키지의 버전 문자열입니다.                             |
| `package_type` | 패키지의 타입입니다(예: `generic`, `npm`, `maven`). |
| `created_at`   | 패키지가 생성된 타임스탬프입니다.                    |

추가 구성이 필요하지 않습니다. 프로젝트의 패키지 레지스트리에 릴리스 태그와 일치하는 버전의 패키지가 있으면, 증거가 수집될 때 자동으로 포함됩니다.

## 릴리스 증거 수집 {#collect-release-evidence}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

릴리스가 생성되면 릴리스 증거가 자동으로 수집됩니다. 다른 시간에 증거 수집을 시작하려면 [API 호출](../../../api/releases/_index.md#collect-release-evidence)을 사용합니다. 한 릴리스에 대해 릴리스 증거를 여러 번 수집할 수 있습니다.

증거 수집 스냅샷은 릴리스 페이지에 증거가 수집된 타임스탬프와 함께 표시됩니다.

## 릴리스 증거로 보고서 아티팩트 포함 {#include-report-artifacts-as-release-evidence}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

릴리스를 생성할 때 [작업 아티팩트](../../../ci/yaml/_index.md#artifactsreports)가 실행된 마지막 파이프라인에 포함되면, 이들은 자동으로 릴리스 증거로 릴리스에 포함됩니다.

작업 아티팩트는 일반적으로 만료되지만, 릴리스 증거에 포함된 아티팩트는 만료되지 않습니다.

작업 아티팩트 수집을 활성화하려면 다음 두 가지를 모두 지정해야 합니다:

1. [`artifacts:paths`](../../../ci/yaml/_index.md#artifactspaths)
1. [`artifacts:reports`](../../../ci/yaml/_index.md#artifactsreports)

```yaml
ruby:
  script:
    - gem install bundler
    - bundle install
    - bundle exec rspec --format progress --format RspecJunitFormatter --out rspec.xml
  artifacts:
    paths:
      - rspec.xml
    reports:
      junit: rspec.xml
```

파이프라인이 성공적으로 실행되면, 릴리스를 생성할 때 `rspec.xml` 파일이 릴리스 증거로 저장됩니다.

릴리스 증거 수집을 [예약](#schedule-release-evidence-collection)하는 경우, 일부 아티팩트가 증거 수집 시간까지 이미 만료되었을 수 있습니다. 이를 피하려면 [`artifacts:expire_in`](../../../ci/yaml/_index.md#artifactsexpire_in) 키워드를 사용할 수 있습니다. 자세한 내용은 [이슈 222351](https://gitlab.com/gitlab-org/gitlab/-/issues/222351)을 참조합니다.

## 릴리스 증거 수집 예약 {#schedule-release-evidence-collection}

API에서:

- 향후 `released_at` 날짜를 지정하면 릴리스는 **예정된 릴리스**가 되고 증거는 릴리스 날짜에 수집됩니다. 그 전에는 릴리스 증거를 수집할 수 없습니다.
- 과거 `released_at` 날짜를 지정하면 릴리스는 **과거 릴리스**가 되고 증거가 수집되지 않습니다.
- `released_at` 날짜를 지정하지 않으면 릴리스 증거는 릴리스가 생성되는 날짜에 수집됩니다.
