---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Kubernetes 연산자를 사용하여 Google Kubernetes Engine에서 CI/CD 작업을 실행하도록 GitLab Runner를 구성하는 방법을 알아봅니다.
title: '자습서: Google Kubernetes Engine을 사용하도록 GitLab Runner 구성'
---

이 튜토리얼에서는 Google Kubernetes Engine(GKE)을 사용하여 작업을 실행하도록 GitLab Runner를 구성하는 방법을 설명합니다.

이 튜토리얼에서는 [표준 클러스터 모드](https://docs.cloud.google.com/kubernetes-engine/docs/concepts/configuration-overview)에서 작업을 실행하도록 GitLab Runner를 구성합니다.

GitLab Runner를 GKE를 사용하도록 구성하려면:

1. [환경 설정](#set-up-your-environment).
1. [클러스터 생성 및 연결](#create-and-connect-to-a-cluster).
1. [Kubernetes 연산자 설치 및 구성](#install-and-configure-the-kubernetes-operator).
1. 선택사항. [구성이 성공적이었는지 확인](#verify-your-configuration).

## 시작하기 전에 {#before-you-begin}

GitLab Runner를 GKE를 사용하도록 구성하기 전에 다음을 수행해야 합니다:

- Maintainer 또는 Owner 역할이 있는 프로젝트가 필요합니다. 프로젝트가 없으면 [생성](../../user/project/_index.md)할 수 있습니다.
- [프로젝트 러너 인증 토큰 획득](../../ci/runners/runners_scope.md#create-a-project-runner-with-a-runner-authentication-token).
- GitLab Runner를 설치합니다.

## 환경 설정 {#set-up-your-environment}

GKE에서 GitLab Runner를 구성하고 사용하기 위한 도구를 설치합니다.

1. [Google Cloud CLI 설치 및 구성](https://cloud.google.com/sdk/docs/install). Google Cloud CLI를 사용하여 클러스터에 연결합니다.
1. [kubectl 설치 및 구성](https://kubernetes.io/docs/tasks/tools/). kubectl을 사용하여 로컬 환경에서 원격 클러스터와 통신합니다.

## 클러스터 생성 및 연결 {#create-and-connect-to-a-cluster}

이 단계에서는 클러스터를 생성하고 연결하는 방법을 설명합니다. 클러스터에 연결한 후 kubectl을 사용하여 상호 작용합니다.

1. Google Cloud Platform에서 [표준](https://docs.cloud.google.com/kubernetes-engine/docs/how-to/creating-a-zonal-cluster) 클러스터를 생성합니다.
1. kubectl 인증 플러그인을 설치합니다:

   ```shell
   gcloud components install gke-gcloud-auth-plugin
   ```

1. 클러스터에 연결합니다:

   ```shell
   gcloud container clusters get-credentials CLUSTER_NAME --zone=CLUSTER_LOCATION
   ```

1. 클러스터 구성을 봅니다:

   ```shell
   kubectl config view
   ```

1. 클러스터에 연결되어 있는지 확인합니다:

   ```shell
   kubectl config current-context
   ```

## Kubernetes 연산자 설치 및 구성 {#install-and-configure-the-kubernetes-operator}

클러스터를 보유하고 있으므로 이제 Kubernetes 연산자를 설치하고 구성할 준비가 되었습니다.

1. `cert-manager`을 설치합니다. 이미 인증서 관리자가 설치되어 있으면 이 단계를 건너뜁니다:

   ```shell
   kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.7.1/cert-manager.yaml
   ```

1. 클러스터에서 실행되는 Kubernetes 연산자를 관리하는 도구인 Operator Lifecycle Manager(OLM)를 설치합니다:

   ```shell
   curl --silent --location "https://github.com/operator-framework/operator-lifecycle-manager/releases/download/v0.24.0/install.sh" \
    | bash -s v0.24.0
   ```

1. Kubernetes 연산자를 설치합니다:

   ```shell
   kubectl create -f https://operatorhub.io/install/gitlab-runner-operator.yaml
   ```

1. Operator Lifecycle Manager v0.25.0 이상만 해당합니다. 자신의 인증서 관리자를 추가하거나 `cert-manager`을 사용합니다.

   - 자신의 인증서 제공자를 추가하려면:

     1. `gitlab-runner-operator.yaml`에서 `env` 설정의 인증서 네임스페이스 및 인증서 이름을 정의합니다:

        ```shell
        cat > gitlab-runner-operator.yaml << EOF
        apiVersion: operators.coreos.com/v1alpha1
        kind: Subscription
        metadata:
        name: gitlab-runner-operator
        namespace: gitlab-ns
        spec:
        channel: stable
        name: gitlab-runner-operator
        source: operatorhubio-catalog
        ca: webhook-server-cert
        sourceNamespace: olm
        config:
        env:
           - name: CERTIFICATE_NAMESPACE
             value: cert_namespace_desired_value
           - name: CERTIFICATE_NAME
           value: cert_name_desired_value
        EOF
        ```

     1. `gitlab-runner-operator.yaml`을 Kubernetes 클러스터에 적용합니다:

        ```shell
        kubectl apply -f gitlab-runner-operator.yaml
        ```

   - `cert-manager`을 사용하려면:

     1. `certificate-issuer-install.yaml`을 사용하여 연산자 설치 외에도 기본 네임스페이스에 `Certificate` 및 `Issuer`을 설치합니다:

        ```shell
        cat > certificate-issuer-install.yaml << EOF
        apiVersion: v1
        kind: Namespace
        metadata:
        labels:
           app.kubernetes.io/component: controller-manager
           app.kubernetes.io/managed-by: olm
           app.kubernetes.io/name: gitlab-runner-operator
        name: gitlab-runner-system
        ---
        apiVersion: cert-manager.io/v1
        kind: Certificate
        metadata:
        name: gitlab-runner-serving-cert
        namespace: gitlab-runner-system
        spec:
        dnsNames:
        - gitlab-runner-webhook-service.gitlab-runner-system.svc
        - gitlab-runner-webhook-service.gitlab-runner-system.svc.cluster.local
        issuerRef:
          kind: Issuer
          name: gitlab-runner-selfsigned-issuer
        secretName: webhook-server-cert
        ---
        apiVersion: cert-manager.io/v1
        kind: Issuer
        metadata:
        name: gitlab-runner-selfsigned-issuer
        namespace: gitlab-runner-system
        spec:
        selfSigned: {}
        EOF
        ```

     1. `certificate-issuer-install.yaml`을 Kubernetes 클러스터에 적용합니다:

        ```shell
        kubectl create -f certificate-issuer-install.yaml
        ```

1. GitLab 프로젝트의 `runner-registration-token`을 포함하는 시크릿을 생성합니다:

   ```shell
    cat > gitlab-runner-secret.yml << EOF
    apiVersion: v1
    kind: Secret
    metadata:
      name: gitlab-runner-secret
    type: Opaque
    stringData:
      runner-token: YOUR_RUNNER_AUTHENTICATION_TOKEN
    EOF
   ```

1. 시크릿을 적용합니다:

   ```shell
   kubectl apply -f gitlab-runner-secret.yml
   ```

1. 사용자 정의 리소스 정의 파일을 생성하고 다음 정보를 포함합니다:

   ```shell
    cat > gitlab-runner.yml << EOF
    apiVersion: apps.gitlab.com/v1beta2
    kind: Runner
    metadata:
      name: gitlab-runner
    spec:
      gitlabUrl: https://gitlab.example.com
      buildImage: alpine
      token: gitlab-runner-secret
    EOF
   ```

1. 사용자 정의 리소스 정의 파일을 적용합니다:

   ```shell
   kubectl apply -f gitlab-runner.yml
   ```

완료되었습니다! GitLab Runner를 GKE를 사용하도록 구성했습니다. 다음 단계에서 구성이 작동하는지 확인할 수 있습니다.

## 구성 확인 {#verify-your-configuration}

GKE 클러스터에서 러너가 실행 중인지 확인하려면 다음 중 하나를 수행합니다:

- 다음 명령을 사용합니다:

  ```shell
  kubectl get pods
  ```

  다음 출력이 표시되어야 합니다. 이는 러너가 GKE 클러스터에서 실행 중임을 보여줍니다:

  ```plaintext
  NAME                             READY   STATUS    RESTARTS   AGE
  gitlab-runner-hash-short_hash    1/1     Running   0          5m
  ```

- GitLab에서 작업 로그를 확인합니다:
  1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
  1. **빌드** > **작업**를 선택하고 작업을 찾습니다.
  1. 작업 로그를 보려면 작업 상태를 선택합니다.
