---
stage: AI Platform
group: AI Core Infra
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: AI Gateway의 문제를 해결합니다.
title: AI Gateway 문제 해결
---

[AI Gateway](install_ai_gateway.md)를 사용하여 작업할 때 다음의 문제가 발생할 수 있습니다.

## OpenShift 권한 문제 {#openshift-permission-issues}

OpenShift에 AI Gateway를 배포할 때 OpenShift 보안 모델로 인해 권한 오류가 발생할 수 있습니다.

### `/tmp`에서 읽기 전용 파일 시스템 {#read-only-file-system-at-tmp}

AI Gateway는 `/tmp`에 씁니다. 하지만 보안이 제한된 OpenShift 환경을 기반으로 `/tmp`는 읽기 전용일 수 있습니다.

이 문제를 해결하려면 새 `EmptyDir` 볼륨을 만들고 다음 방법 중 하나로 `/tmp`에 마운트합니다:

- 명령줄에서:

  ```shell
  oc set volume <object_type>/<name> --add --name=tmpVol --type=emptyDir --mountPoint=/tmp
  ```

- `values.yaml`에서:

  ```yaml
  volumes:
  - name: tmp-volume
    emptyDir: {}

  volumeMounts:
  - name: tmp-volume
    mountPath: "/tmp"
  ```

### HuggingFace 모델 {#huggingface-models}

기본적으로 AI Gateway는 HuggingFace 모델을 캐시하기 위해 `/home/aigateway/.hf`을(를) 사용하며, 이는 OpenShift의 보안이 제한된 환경에서 쓰기 불가능할 수 있습니다. 다음과 같은 권한 오류가 발생할 수 있습니다:

```shell
[Errno 13] Permission denied: '/home/aigateway/.hf/...'
```

이 문제를 해결하려면 `HF_HOME` 환경 변수를 쓰기 가능한 위치로 설정합니다. `/var/tmp/huggingface`을(를) 사용하거나 다음 방법 중 하나로 컨테이너에서 쓸 수 있는 다른 디렉터리를 사용할 수 있습니다:

- `values.yaml`에서:

  ```yaml
  extraEnvironmentVariables:
    - name: HF_HOME
      value: /var/tmp/huggingface  # Use any writable directory
  ```

- Helm 업그레이드 명령에서:

  ```shell
  --set "extraEnvironmentVariables[0].name=HF_HOME" \
  --set "extraEnvironmentVariables[0].value=/var/tmp/huggingface"  # Use any writable directory
  ```

이 설정은 AI Gateway가 HuggingFace 모델을 적절히 캐시하면서 OpenShift 보안 제약을 존중할 수 있도록 합니다. 선택한 정확한 디렉터리는 특정 OpenShift 구성 및 보안 정책에 따라 다를 수 있습니다.

## 볼륨 마운트에서 가려진 토크나이저 캐시 {#tokenizer-cache-shadowed-by-a-volume-mount}

AI Gateway 이미지의 사전 캐시된 토크나이저 파일은 다음의 경우 볼륨 마운트에서 가려질 수 있습니다:

- 코드 완성 요청이 `500` 오류를 반환합니다.
- AI Gateway 로그는 `transformers/utils/hub.py`의 `OSError`가 `huggingface.co`에서 `Salesforce/codegen2-16B`를 다운로드하려고 시도하는 것으로 표시합니다.

자체 호스팅 AI Gateway 이미지(`self-hosted-vX.Y.Z-ee`)는 `HF_HUB_OFFLINE=true`을(를) 설정하고 빌드 시 토크나이저를 사전 캐시하므로 런타임에 `huggingface.co`에 대한 네트워크 액세스가 발생하지 않아야 합니다. 네트워크 액세스가 발생하면 Helm 값의 빈 디렉터리가 `/home/aigateway/.hf`에 마운트되어 캐시된 파일을 덮어쓸 수 있습니다.

`huggingface.co`에 대한 송신 액세스를 부여하여 이 문제를 해결하려고 시도하지 마세요. 대신 문제를 진단하려면 AI Gateway 포드에서 다음을 실행합니다:

```shell
ls -la /home/aigateway/.hf/hub/ 2>/dev/null || echo "NO_CACHE_DIR"
env | grep -E '^(HF_|TRANSFORMERS_)'
```

캐시 디렉터리가 없거나 비어 있으면 다음을 수행합니다:

1. `values.yaml`을(를) 확인하여 `/home/aigateway/.hf` 또는 `HF_HOME`에서 설정한 경로를 대상으로 하는 `volumeMounts`을(를) 찾습니다.
1. 이미지의 기본 제공 캐시와 겹치지 않는 디렉터리로 마운트를 제거하거나 다시 매핑합니다.

## 자체 서명 인증서 오류 {#self-signed-certificate-error}

AI Gateway가 사용자 정의 인증 기관(CA) 또는 자체 서명 인증서로 서명된 인증서가 있는 GitLab 인스턴스 또는 모델 엔드포인트에 연결하려고 할 때 다음 오류가 발생할 수 있습니다:

```plaintext
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain
```

이 문제를 해결하려면 [자체 서명 SSL 인증서로 GitLab 인스턴스 또는 모델 엔드포인트에 연결](install_ai_gateway.md#connect-to-a-gitlab-instance-or-model-endpoint-with-a-self-signed-ssl-certificate)을(를) 참조하세요.

## 토큰 생성 실패 {#token-creation-failed}

GitLab Duo Chat과 같은 기능을 사용할 때 `Token creation failed` 오류가 발생하면 `AIGW_SELF_SIGNED_JWT__SIGNING_KEY` 및 `AIGW_SELF_SIGNED_JWT__VALIDATION_KEY` 환경 변수가 AI Gateway에서 설정되지 않았을 수 있습니다.

이러한 키는 AI Gateway가 수명이 짧은 사용자 JWT를 발급하는 데 필요합니다. 이러한 키가 없으면 AI Gateway는 토큰에 서명할 수 없으므로 JWK 역직렬화 실패가 발생합니다.

이 이슈를 해결하려면:

1. 필요한 키를 생성합니다:

   ```shell
   openssl genrsa -out aigw_signing.key 2048
   openssl genrsa -out aigw_validation.key 2048
   ```

1. 환경 변수로 전달하여 AI Gateway 컨테이너에 키를 추가합니다:

   ```shell
   -e AIGW_SELF_SIGNED_JWT__SIGNING_KEY="$(cat aigw_signing.key)" \
   -e AIGW_SELF_SIGNED_JWT__VALIDATION_KEY="$(cat aigw_validation.key)"
   ```

1. AI Gateway 컨테이너를 다시 시작합니다.

## PEM 파일을 로드할 때 SSL 인증서 오류 {#ssl-certificate-errors-when-loading-pem-files}

PEM 파일을 Docker 컨테이너에 로드할 때 `JWKError` 오류가 발생하면 SSL 인증서 오류를 해결해야 할 수 있습니다.

이 문제를 해결하려면 다음 환경 변수를 사용하여 Docker 컨테이너에서 적절한 인증서 번들 경로를 설정합니다:

- `SSL_CERT_FILE=/path/to/ca-bundle.pem`
- `REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem`

`/path/to/ca-bundle.pem`을(를) 인증서 번들의 경로로 바꿉니다.

## 오프라인 GitLab 인스턴스로 청구 이벤트를 보낼 때 오류 {#errors-when-sending-billing-events-to-an-offline-gitlab-instance}

오프라인 환경에서 AI Gateway는 GitLab 인스턴스의 `/api/v4/ai/billable_usage/events` API 엔드포인트로 이벤트를 보냅니다. 요청이 실패하면 AI Gateway 로그에서 응답 상태를 확인합니다:

- `401`: `AIGW_BILLING_EVENT__API_KEY`이(가) 설정되지 않았거나 토큰이 유효하지 않습니다.
- `403`: 토큰에 [`ai_features` 범위](../security/tokens/access_token_scopes.md)가 없거나 [서비스 계정](../user/profile/service_accounts.md#create-a-service-account)에 속하지 않습니다.
- `404`: `local_billing_persistence` 기능 플래그가 비활성화되었거나 GitLab 인스턴스가 오프라인 라이센스를 사용하지 않습니다.

자세한 내용은 [GitLab 인스턴스로 청구 이벤트 보내기](install_ai_gateway.md#send-billing-events-to-an-offline-gitlab-instance)를 참조하세요.
