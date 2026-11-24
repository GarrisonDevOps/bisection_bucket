---
stage: Verify
group: Mobile DevOps
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Apple App Store Connect
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 기능은 GitLab에서 개발한 [Mobile DevOps](../../../ci/mobile_devops/_index.md)의 일부입니다. 이 기능은 아직 개발 중이지만 다음을 수행할 수 있습니다:

- [기능 요청](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=feature_request).
- [버그 보고](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=report_bug).
- [피드백 공유](https://gitlab.com/gitlab-org/incubation-engineering/mobile-devops/feedback/-/issues/new?description_template=general_feedback).

Apple App Store Connect 통합을 사용하여 [App Store Connect](https://appstoreconnect.apple.com)에 연결하도록 CI/CD 파이프라인을 구성합니다. 이 통합을 통해 iOS, iPadOS, macOS, tvOS 및 watchOS용 앱을 빌드하고 릴리스할 수 있습니다.

Apple App Store Connect 통합은 [fastlane](https://fastlane.tools/)과 함께 기본 제공됩니다. 다른 빌드 도구로도 이 통합을 사용할 수 있습니다.

## GitLab에서 통합 활성화 {#enable-the-integration-in-gitlab}

사전 요구 사항:

- [Apple Developer Program](https://developer.apple.com/programs/enroll/)에 등록된 Apple ID가 있어야 합니다.
- Apple App Store Connect 포털에서 프로젝트용 [새 개인 키를 생성](https://developer.apple.com/documentation/appstoreconnectapi/creating_api_keys_for_app_store_connect_api)해야 합니다.

GitLab에서 Apple App Store Connect 통합을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Apple App Store Connect**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. Apple App Store Connect 구성 정보를 입력합니다:
   - **발급자 ID**: Apple App Store Connect 발급자 ID입니다.
   - **키 ID**: 생성된 개인 키의 키 ID입니다.
   - **개인 키**: 생성된 개인 키입니다. 이 키는 한 번만 다운로드할 수 있습니다.
   - **보호된 브랜치 및 태그만**: 보호된 브랜치 및 태그에서만 변수를 설정하려면 활성화합니다.
1. **변경 사항 저장**을 선택합니다.

통합을 활성화한 후:

- 전역 변수 `$APP_STORE_CONNECT_API_KEY_ISSUER_ID`, `$APP_STORE_CONNECT_API_KEY_KEY_ID`, `$APP_STORE_CONNECT_API_KEY_KEY` 및 `$APP_STORE_CONNECT_API_KEY_IS_KEY_CONTENT_BASE64`가 CI/CD 사용을 위해 생성됩니다.
- `$APP_STORE_CONNECT_API_KEY_KEY`에는 Base64로 인코딩된 개인 키가 포함됩니다.
- `$APP_STORE_CONNECT_API_KEY_IS_KEY_CONTENT_BASE64`은 항상 `true`입니다.

## 보안 고려 사항 {#security-considerations}

### CI/CD 변수 보안 {#cicd-variable-security}

`.gitlab-ci.yml` 파일에 푸시된 악성 코드는 `$APP_STORE_CONNECT_API_KEY_KEY`를 포함한 변수를 손상시킬 수 있으며 타사 서버로 전송할 수 있습니다. 자세한 내용은 [CI/CD 변수 보안](../../../ci/variables/_index.md#cicd-variable-security)을 참조하세요.

## fastlane에서 통합 활성화 {#enable-the-integration-in-fastlane}

fastlane에서 통합을 활성화하고 TestFlight 또는 공개 App Store 릴리스를 업로드하려면 앱의 `fastlane/Fastfile`에 다음 코드를 추가할 수 있습니다:

```ruby
app_store_connect_api_key
```
