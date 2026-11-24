---
stage: Developer Experience
group: API Platform
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: OpenAPI
description: "OpenAPI 3.0 사양을 사용하여 GitLab REST API 탐색"
---

GitLab은 [OpenAPI 3.0 사양](https://spec.openapis.org/oas/v3.0.3)을 사용하여 REST API를 문서화합니다. 이는 RESTful API를 설명하기 위한 표준 플랫폼 독립적 형식(이전에 Swagger라고 불렀음)입니다. API 코드는 REST API의 단일 정보 출처입니다. OpenAPI 사양은 API 코드에서 직접 자동 생성되며 구현과 긴밀하게 연결되어 있으므로 문서가 항상 정확하고 최신 상태로 유지됩니다.

GitLab API에 대한 일반 정보는 [GitLab 확장](../_index.md)을 참조하세요.

## OpenAPI 사양 파일 {#openapi-specification-file}

원본 OpenAPI 3.0 사양은 GitLab monorepo에서 사용할 수 있습니다:

- **파일:** [`doc/api/openapi/openapi_v3.yaml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/doc/api/openapi/openapi_v3.yaml)
- **형식:** OpenAPI 3.0(YAML)

> [!note]
> OpenAPI 2.0 사양(`openapi_v2.yaml`)은 더 이상 사용되지 않으며 업데이트를 받지 않습니다. 대신 OpenAPI 3.0 사양(`openapi_v3.yaml`)을 사용하세요.

## 대화형 REST API 문서 {#interactive-rest-api-documentation}

REST API는 OpenAPI 3.0 사양을 사용하여 완전히 문서화됩니다. [REST API 문서](https://api.gitlab.com/rest/)에서 모든 엔드포인트를 대화형으로 탐색하고 테스트할 수 있습니다.

문서는 오픈 소스 API 참조 도구인 [Scalar](https://scalar.com/)를 사용하여 렌더링됩니다. GitLab 소스 코드의 OpenAPI 사양에서 자동으로 생성되므로 항상 API의 현재 상태를 반영합니다.

### 권한 부여 자격증명 추가 {#add-authorization-credentials}

일부 엔드포인트는 인증이 필요합니다. GitLab은 HTTP Bearer 또는 OAuth 2.0 자격증명을 사용한 인증을 지원합니다.

권한 부여 자격증명을 추가하려면:

1. [REST API 문서](https://api.gitlab.com/rest/)로 이동합니다.
1. 오른쪽의 **인증** 패널에서 드롭다운 목록의 인증 방법을 선택합니다.
1. 자격증명을 입력합니다:
   - `http`의 경우 [개인 액세스 토큰](../../user/profile/personal_access_tokens.md)을 입력합니다.
   - `oauth2`의 경우 GitLab을 ID 공급자로 사용하는 인증 코드 흐름을 사용합니다.
1. **권한 부여**를 선택합니다.

자격증명은 세션 중에 모든 후속 요청에 대해 자동으로 재사용됩니다.

### 실시간 요청 전송 {#send-a-live-request}

대화형 요청 도구를 사용하여 GitLab에 실시간 요청을 전송합니다.

실시간 요청을 전송하려면:

1. [REST API 문서](https://api.gitlab.com/rest/)로 이동합니다.
1. 작업을 확장합니다.
1. **Test Request**를 선택합니다.
1. 필수 또는 선택적 매개변수를 입력합니다.
1. **전송**을 선택합니다.

도구는 `curl` 명령, 전체 요청 URL 및 서버 응답을 표시합니다.
