---
stage: Software Supply Chain Security
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments
description: "자체 호스팅되는 Sigstore 스택을 사용하여 CI/CD 아티팩트 및 컨테이너 이미지에 서명하고, Fulcio 구성 및 문제 해결을 포함합니다."
title: 자체 호스팅되는 Sigstore를 사용하여 아티팩트 및 컨테이너 이미지에 서명
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

GitLab Self-Managed를 실행하는 경우, 공용 [Sigstore 서비스](signing_examples.md)를 사용하여 CI/CD 아티팩트 및 컨테이너 이미지에 서명할 수 없습니다. 서비스는 GitLab.com 파이프라인만 신뢰하며, 자신의 인스턴스의 파이프라인은 신뢰하지 않습니다. 대신 자신의 Sigstore 인프라(Fulcio, Rekor, Certificate Transparency 로그)를 GitLab 인스턴스에 연결하여 GitLab.com 또는 인터넷에 의존하지 않고 Cosign으로 아티팩트에 서명하고 검증할 수 있습니다.

GitLab OpenID Connect(OIDC) 제공자가 신원을 증명하고, Cosign은 서명 키를 사용 직후 폐기하며, Rekor은 모든 서명 이벤트를 투명성 로그에 기록합니다.

Fulcio가 발급한 인증서는 서명에 포함되며, 프로젝트 경로, 커밋 SHA, 파이프라인 소스, 러너 환경, 작업 URL을 포함하여 정확히 어느 파이프라인이 이를 생성했는지에 대한 세부 정보가 함께 포함됩니다.

전제 조건:

- Sigstore 인프라(Fulcio, Rekor)와 GitLab CI/CD 러너를 구성할 수 있는 액세스 권한
- 네트워크에서 실행 중인 자체 호스팅되는 Sigstore 스택(Fulcio, Rekor, Certificate Transparency 로그 포함) Certificate Transparency 로그는 필수입니다. Cosign은 검증 중에 서명된 인증서 타임스탬프를 확인하므로, Certificate Transparency 로그 없이 배포된 Fulcio는 Cosign이 검증할 수 없는 인증서를 발급합니다. 배포 지침은 다음을 참조하세요:
  - [Sigstore 투명성 로그 설치 가이드](https://docs.sigstore.dev/logging/installation/)(Rekor 및 해당 Trillian 백엔드용)
  - [Fulcio 리포지토리](https://github.com/sigstore/fulcio)(Fulcio 및 Certificate Transparency 로그용)
- GitLab 인스턴스가 프라이빗 인증 기관이 있는 HTTPS를 사용하는 경우, 해당 인증 기관은 Fulcio와 CI/CD 러너 모두에서 신뢰해야 합니다:
  - Fulcio 컨테이너에 마운트된 인증 기관 인증서(경로로 설정된 `SSL_CERT_FILE`)
  - 각 러너의 운영 체제 신뢰 저장소에 설치된 인증 기관 인증서
- [Cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v2.x 이상이 CI/CD 러너에 설치됨
- Sigstore 스택의 신뢰 자료 파일(러너의 `/etc/sigstore/`과 같은 공유 위치에 배치됨):
  - Fulcio 루트 CA 인증서(`fulcio-root.pem`)
  - Rekor 투명성 로그 공개 키(`rekor-pub.pem`)
  - Certificate Transparency 로그 공개 키(`ctfe-pub.pem`)

## GitLab 인스턴스를 신뢰하도록 Fulcio 구성 {#configure-fulcio-to-trust-your-gitlab-instance}

키 없는 서명 중에 GitLab CI/CD 작업의 OIDC 토큰을 검증할 수 있도록 GitLab 인스턴스를 신뢰하도록 Fulcio를 구성합니다. Fulcio는 토큰의 클레임을 서명 인증서의 필드에 매핑합니다. 구성 파일에는 `oidc-issuers` 섹션과 `ci-issuer-metadata` 섹션 모두가 필요합니다.

Fulcio를 구성하려면:

1. 다음 명령을 사용하여 정확한 OIDC 발급자 URL을 검색합니다. `https://gitlab.example.com`을(를) GitLab 인스턴스의 URL로 바꿉니다. Fulcio는 정확한 일치를 요구합니다. 스키마와 후행 슬래시의 유무 모두 중요합니다.

   ```shell
   curl --silent "https://gitlab.example.com/.well-known/openid-configuration" | jq --raw-output .issuer
   ```

1. GitLab 인스턴스에 대한 `oidc-issuers` 항목이 있는 Fulcio OIDC 구성 파일을 생성합니다. `<gitlab_issuer_url>`을(를) 이전 단계의 출력으로 바꿉니다:

   ```yaml
   oidc-issuers:
     <gitlab_issuer_url>:
       issuer-url: <gitlab_issuer_url>
       client-id: sigstore
       type: ci-provider
       ci-provider: gitlab-pipeline
       contact: admin@example.com
       description: "GitLab Self-Managed OIDC"
   ```

1. 같은 파일에서 `ci-issuer-metadata` 섹션을 추가하고 [업스트림 Fulcio 구성](https://github.com/sigstore/fulcio/blob/main/config/identity/config.yaml)에서 복사된 GitLab 클레임 템플릿을 포함합니다. `<gitlab_issuer_url>`을(를) 이전 단계에서 사용한 것과 동일한 값으로 바꿉니다.

   각 클레임이 매핑되는 항목을 보려면 [OIDC 토큰 클레임을 Fulcio OID로 매핑](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#mapping-oidc-token-claims-to-fulcio-oids)의 GitLab 열을 참조하세요.

   ```yaml
   ci-issuer-metadata:
     gitlab-pipeline:
       default-template-values:
         url: "<gitlab_issuer_url>"
         environment: ""
       extension-templates:
         build-signer-uri: "https://{{ .ci_config_ref_uri }}"
         build-signer-digest: "ci_config_sha"
         runner-environment: "runner_environment"
         source-repository-uri: "{{ .url }}/{{ .project_path }}"
         source-repository-digest: "sha"
         source-repository-ref: >-
           refs/{{if eq .ref_type "branch"}}heads/{{ else }}tags/{{end}}{{ .ref }}
         source-repository-identifier: "project_id"
         source-repository-owner-uri: "{{ .url }}/{{ .namespace_path }}"
         source-repository-owner-identifier: "namespace_id"
         build-config-uri: "https://{{ .ci_config_ref_uri }}"
         build-config-digest: "ci_config_sha"
         build-trigger: "pipeline_source"
         run-invocation-uri: >-
           {{ .url }}/{{ .project_path }}/-/jobs/{{ .job_id }}
         source-repository-visibility-at-signing: "project_visibility"
         deployment-environment: "environment"
       subject-alternative-name-template: "https://{{ .ci_config_ref_uri }}"
   ```

   > [!note]
   > 이 섹션은 Sigstore 프로젝트에 의해 유지되며, GitLab에 의해서는 유지되지 않습니다. 업스트림 파일의 변경 사항을 정기적으로 확인하고 사본을 업데이트하여 일치시킵니다.

## 재시작 중에 키와 로그를 유지하도록 Rekor 구성 {#configure-rekor-to-keep-its-key-and-log-across-restarts}

기본적으로 Rekor는 매번 시작할 때마다 새로운 서명 키를 생성하고 새로운 빈 로그 트리를 생성합니다. 재시작 중에 둘 다 유지하려면 지속적인 서명자와 고정된 트리 ID로 Rekor를 구성합니다.

Rekor를 구성하려면:

1. Rekor가 실행 중인 동안 현재 로그의 트리 ID를 가져옵니다:

   ```shell
   curl --silent "http://<sigstore-host>:3000/api/v1/log" | jq --raw-output .treeID
   ```

1. Rekor를 시작하는 `rekor-server serve` 명령에 이 플래그들을 추가한 다음 Rekor를 다시 시작합니다:

   ```plaintext
   --rekor_server.signer=<signer>
   --trillian_log_server.tlog_id=<tree_id>
   ```

   바꿀 항목:

   - `<signer>`을(를) HashiCorp Vault 전송 키의 `hashivault://<key_name>`과(와) 같은 키 관리 서비스 URI로 바꿉니다. Vault의 경우, Rekor에 대해 `VAULT_ADDR` 및 `VAULT_TOKEN` 환경 변수도 설정합니다. Rekor는 또한 PEM으로 인코딩된 개인 키 파일의 경로를 허용합니다. Rekor 명령 도움말은 파일 기반 서명자는 테스트용으로만 사용해야 한다고 말합니다.
   - `<tree_id>`을(를) 이전 단계의 트리 ID로 바꿉니다.

1. 서명자를 변경한 경우, 새로운 Rekor 공개 키로 신뢰 자료를 다시 빌드합니다. 명령은 [오류: `not enough verified log entries from transparency log`](#error-not-enough-verified-log-entries-from-transparency-log)를 참조하세요.

> [!warning]
> 지속적인 서명자가 있고 트리 ID가 없어도 재시작 후 서명이 계속 작동합니다. 하지만 Rekor는 더 이상 재시작 전에 기록된 항목을 반환하지 않으며, 새 항목은 로그 인덱스 `0`에서 다시 시작됩니다.

## 아티팩트 및 컨테이너 이미지에 서명 {#sign-artifacts-and-container-images}

`id_tokens` 키워드를 사용하여 작업에 대한 OIDC 토큰을 생성합니다. Cosign은 이 토큰을 Fulcio에 제시하고, Fulcio는 임시 서명 인증서를 발급합니다.

Cosign v3는 서명 구성 파일을 사용하여 Sigstore 서비스 엔드포인트와 신뢰 자료를 지정합니다. 이 파일들을 한 번 생성하여 러너에 배포하거나 다음 예에 표시된 대로 각 작업에서 생성합니다.

```yaml
sign-artifact:
  stage: sign
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore
  variables:
    COSIGN_YES: "true"
  script:
    - cosign signing-config create
        --fulcio="url=http://<sigstore-host>:5555,api-version=1,start-time=2024-01-01T00:00:00Z,operator=my-org"
        --rekor="url=http://<sigstore-host>:3000,api-version=1,start-time=2024-01-01T00:00:00Z,operator=my-org"
        --rekor-config="ANY"
        --oidc-provider="url=https://gitlab.example.com,api-version=1,start-time=2024-01-01T00:00:00Z,operator=my-org"
        --out signing-config.json
    - cosign trusted-root create
        --fulcio="url=http://<sigstore-host>:5555,certificate-chain=/etc/sigstore/fulcio-root.pem,start-time=2024-01-01T00:00:00Z"
        --rekor="url=http://<sigstore-host>:3000,public-key=/etc/sigstore/rekor-pub.pem,start-time=2024-01-01T00:00:00Z"
        --ctfe="url=http://<sigstore-host>:6962,public-key=/etc/sigstore/ctfe-pub.pem,start-time=2024-01-01T00:00:00Z"
        --out trusted-root.json
    - cosign sign-blob
        --signing-config=signing-config.json
        --trusted-root=trusted-root.json
        --oidc-client-id=sigstore
        --identity-token=$SIGSTORE_ID_TOKEN
        --bundle=artifact.bundle
        artifact.txt
```

`start-time` 값은 [Sigstore protobuf 사양](https://github.com/sigstore/protobuf-specs)에 정의된 대로 서비스 엔드포인트가 유효한 것으로 간주되는 가장 이른 시간입니다. Sigstore 스택이 배포된 날짜를 사용합니다.

`--oidc-client-id`에서 `sigstore`을(를) Fulcio OIDC 발급자 항목에 구성된 클라이언트 ID로 바꿉니다.

`--oidc-provider`에 Fulcio `oidc-issuers` 구성에 등록한 것과 동일한 발급자 URL을 사용합니다.

### 컨테이너 이미지에 서명 {#sign-container-images}

컨테이너 이미지에 서명하려면 파일 경로 대신 이미지 참조와 함께 `cosign sign`을(를) 사용합니다. 서명 구성은 동일합니다.

컨테이너 레지스트리는 해석 가능한 호스트명의 HTTPS를 통해 연결할 수 있어야 합니다. 레지스트리는 자신의 외부 URL에서 인증 영역을 광고합니다. Cosign은 호스트가 리터럴 프라이빗 또는 링크-로컬 주소인 영역을 거부합니다. `registry_external_url`이(가) 베어 IP 주소인 인스턴스는 파일에는 서명할 수 있지만 컨테이너 이미지에는 서명할 수 없습니다.

### Cosign v2.x {#for-cosign-v2x}

Cosign v2.x를 사용하는 경우, 구성 파일 대신 URL 플래그 및 환경 변수를 사용합니다:

```yaml
sign-artifact:
  stage: sign
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore
  variables:
    COSIGN_YES: "true"
    SIGSTORE_ROOT_FILE: /etc/sigstore/fulcio-root.pem
    SIGSTORE_REKOR_PUBLIC_KEY: /etc/sigstore/rekor-pub.pem
    SIGSTORE_CT_LOG_PUBLIC_KEY_FILE: /etc/sigstore/ctfe-pub.pem
  script:
    - cosign sign-blob
        --fulcio-url=http://<sigstore-host>:5555
        --rekor-url=http://<sigstore-host>:3000
        --oidc-issuer=https://gitlab.example.com
        --identity-token=$SIGSTORE_ID_TOKEN
        --output-signature=artifact.sig
        --output-certificate=artifact.crt
        artifact.txt
```

컨테이너 이미지의 경우, [컨테이너 이미지에 서명](#sign-container-images)에 설명된 대로 Cosign v3를 사용합니다.

Cosign v2는 인증서를 base64로 인코딩된 PEM으로 작성합니다. 다른 도구에 전달하기 전에 디코딩합니다.

`--oidc-issuer`에 Fulcio `oidc-issuers` 구성에 등록한 것과 동일한 발급자 URL을 사용합니다.

## 서명 검증 {#verify-signatures}

Cosign v3 번들의 검증은 신뢰 자료와 예상되는 서명자 신원을 사용합니다:

```shell
cosign verify-blob \
  --trusted-root=trusted-root.json \
  --bundle=artifact.bundle \
  --certificate-oidc-issuer=https://gitlab.example.com \
  --certificate-identity=https://gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main \
  artifact.txt
```

`--certificate-identity` 값은 서명 인증서의 Subject Alternative Name이며, CI/CD 구성 경로에서 빌드됩니다:

```plaintext
https://<CI_SERVER_HOST>/<CI_PROJECT_PATH>//.gitlab-ci.yml@<full ref>
```

그 패턴의 세 가지 세부 사항이 중요합니다:

- 스키마는 항상 `https://`입니다. Fulcio 구성의 `subject-alternative-name-template`이(가) 이를 설정하기 때문입니다. 이는 인스턴스가 HTTP를 통해 접근 가능한 경우에도 유지됩니다.
- `.gitlab-ci.yml` 앞의 이중 슬래시는 정확합니다. 그 앞의 경로 세그먼트는 프로젝트이며, 그 뒤의 빈 세그먼트는 기본 CI/CD 구성 위치를 나타냅니다.
- 완전한 참조는 브랜치 파이프라인의 경우 `refs/heads/<branch>`이고 태그 파이프라인의 경우 `refs/tags/<tag>`입니다.

Cosign v2로 서명된 아티팩트를 검증하려면 분리된 서명 및 인증서를 전달합니다:

```shell
cosign verify-blob \
  --signature=artifact.sig \
  --certificate=artifact.crt \
  --certificate-oidc-issuer=https://gitlab.example.com \
  --certificate-identity=https://gitlab.example.com/my-group/my-project//.gitlab-ci.yml@refs/heads/main \
  artifact.txt
```

## 관련 항목 {#related-topics}

- 공용 Sigstore 인스턴스와 함께 GitLab.com용 [서명 예제](signing_examples.md)
- [CI/CD OIDC ID 토큰](../secrets/id_token_authentication.md)
- [Sigstore: 사용자 정의 구성 요소](https://docs.sigstore.dev/cosign/system_config/custom_components/)

## 문제 해결 {#troubleshooting}

자체 호스팅되는 Sigstore 인프라로 아티팩트에 서명할 때 다음과 같은 문제가 발생할 수 있습니다.

### 오류: `metadata not found for ci provider gitlab-pipeline` {#error-metadata-not-found-for-ci-provider-gitlab-pipeline}

이 오류는 Fulcio 구성에서 `ci-issuer-metadata` 섹션이 누락되었을 때 발생합니다.

이 문제를 해결하려면 [GitLab 인스턴스를 신뢰하도록 Fulcio 구성](#configure-fulcio-to-trust-your-gitlab-instance)에 설명된 대로 전체 `ci-issuer-metadata` 블록을 추가합니다.

### 오류: `ctfe public key not found for payload` {#error-ctfe-public-key-not-found-for-payload}

이 오류는 Cosign이 자체 호스팅되는 스택의 Certificate Transparency 로그 공개 키를 찾을 수 없을 때 발생합니다.

이 문제를 해결하려면 Cosign v3의 `cosign trusted-root create` 명령에 `--ctfe`을(를) 포함하거나 Cosign v2의 `SIGSTORE_CT_LOG_PUBLIC_KEY_FILE` 환경 변수를 설정합니다.

### 오류: `not enough verified log entries from transparency log` {#error-not-enough-verified-log-entries-from-transparency-log}

이 오류는 `trusted-root.json`의 Rekor 공개 키가 더 이상 Rekor 인스턴스가 사용 중인 키와 일치하지 않을 때 발생합니다. 기본 메모리 내 서명자를 사용하면 Rekor는 매번 시작할 때마다 새로운 키를 생성합니다. 따라서 모든 재시작은 신뢰 자료를 무효화하고 다시 빌드될 때까지 모든 작업의 서명이 실패합니다.

이 문제를 해결하려면 실행 중인 인스턴스에서 현재 키를 읽고 신뢰 루트를 다시 생성합니다:

```shell
curl --silent --fail "http://<sigstore-host>:3000/api/v1/log/publicKey" --output /etc/sigstore/rekor-pub.pem
cosign trusted-root create \
  --fulcio="url=http://<sigstore-host>:5555,certificate-chain=/etc/sigstore/fulcio-root.pem,start-time=2024-01-01T00:00:00Z" \
  --rekor="url=http://<sigstore-host>:3000,public-key=/etc/sigstore/rekor-pub.pem,start-time=2024-01-01T00:00:00Z" \
  --ctfe="url=http://<sigstore-host>:6962,public-key=/etc/sigstore/ctfe-pub.pem,start-time=2024-01-01T00:00:00Z" \
  --out trusted-root.json
```

다시 생성된 `trusted-root.json`을(를) 모든 러너에 배포합니다.

이 문제를 방지하려면 [재시작 중에 키와 로그를 유지하도록 Rekor 구성](#configure-rekor-to-keep-its-key-and-log-across-restarts)에 설명된 대로 지속적인 서명자로 Rekor를 구성합니다.

### 오류: `failed to verify signed certificate timestamp` {#error-failed-to-verify-signed-certificate-timestamp}

이 오류는 인증서에 서명된 인증서 타임스탬프가 없을 때 발생하며, Fulcio가 Certificate Transparency 로그 없이 실행될 때 발생합니다. 이 구성에서는 서명이 성공하고 검증만 실패합니다.

이 문제를 해결하려면 Certificate Transparency 로그를 가리키도록 `--ct-log-url`으로 Fulcio를 구성하고 신뢰 루트를 생성할 때 `--ctfe`을(를) 포함합니다.

### 오류: `x509: certificate signed by unknown authority` {#error-x509-certificate-signed-by-unknown-authority}

이 오류는 Fulcio가 GitLab 인스턴스가 제시하는 TLS 인증서를 검증할 수 없을 때 발생합니다.

이 문제를 해결하려면 프라이빗 인증 기관 인증서를 Fulcio 컨테이너에 마운트하고 `SSL_CERT_FILE`을(를) 경로로 설정합니다.

Fulcio `/healthz` 엔드포인트는 OIDC 제공자 초기화에 실패한 경우에도 `SERVING`을(를) 보고합니다. 컨테이너 로그를 사용하여 제공자가 로드되었는지 확인합니다.
