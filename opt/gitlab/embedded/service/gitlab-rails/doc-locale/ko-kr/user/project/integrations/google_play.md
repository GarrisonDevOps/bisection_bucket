---
stage: Verify
group: Mobile DevOps
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Google Play
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 기능은 GitLab에서 개발한 [Mobile DevOps](../../../ci/mobile_devops/_index.md)의 일부입니다. 이 기능은 아직 개발 중이지만 다음을 수행할 수 있습니다:

- [기능 요청](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=feature_request).
- [버그 보고](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=report_bug).
- [피드백 공유](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=general_feedback).

Google Play 통합을 사용하면 CI/CD 파이프라인을 [Google Play Console](https://play.google.com/console/about/)에 연결하여 Android 기기용 앱을 빌드하고 릴리스할 수 있습니다.

Google Play 통합은 [fastlane](https://fastlane.tools/)과 즉시 작동합니다. 다른 빌드 도구와도 이 통합을 사용할 수 있습니다.

## GitLab에서 통합 활성화 {#enable-the-integration-in-gitlab}

사전 요구 사항:

- [Google Play Console](https://play.google.com/console/about/) 개발자 계정이 있어야 합니다.
- Google Cloud 콘솔에서 [프로젝트를 위한 새 서비스 계정 키 생성](https://developers.google.com/android-publisher/getting_started)해야 합니다.

GitLab에서 Google Play 통합을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **구글 플레이**를 선택합니다.
1. **통합 활성화**에서 **활성** 확인란을 선택합니다.
1. **패키지 이름**에 앱의 패키지 이름을 입력합니다(예: `com.gitlab.app_name`).
1. 선택 사항. **보호된 브랜치 및 태그만** 아래에서 **보호된 브랜치 및 태그에만 변수 설정** 확인란을 선택합니다.
1. **서비스 계정 키(.JSON)**에서 키 파일을 드래그하거나 업로드합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

통합을 활성화하면 CI/CD 사용을 위해 전역 변수 `$SUPPLY_PACKAGE_NAME`과 `$SUPPLY_JSON_KEY_DATA`가 생성됩니다.

### CI/CD 변수 보안 {#cicd-variable-security}

`.gitlab-ci.yml` 파일에 푸시된 악의적인 코드는 `$SUPPLY_JSON_KEY_DATA`를 포함한 변수를 손상시킬 수 있으며 이를 제3자 서버로 전송할 수 있습니다. 자세한 내용은 [CI/CD 변수 보안](../../../ci/variables/_index.md#cicd-variable-security)을 참조하세요.

## fastlane에서 통합 활성화 {#enable-the-integration-in-fastlane}

fastlane에서 통합을 활성화하고 Google Play에서 주어진 트랙에 빌드를 업로드하려면 앱의 `fastlane/Fastfile`에 다음 코드를 추가할 수 있습니다:

```ruby
upload_to_play_store(
  track: 'internal',
  aab: '../build/app/outputs/bundle/release/app-release.aab'
)
```
