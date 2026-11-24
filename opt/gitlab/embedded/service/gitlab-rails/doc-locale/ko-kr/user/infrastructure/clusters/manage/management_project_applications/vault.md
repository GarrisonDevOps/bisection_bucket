---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 클러스터 관리 프로젝트를 사용하여 Vault 설치
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[HashiCorp Vault](https://www.vaultproject.io/)는 시크릿 관리 솔루션으로 비밀번호, 자격 증명, 인증서 등을 안전하게 관리하고 저장하는 데 사용할 수 있습니다. Vault 설치는 애플리케이션, GitLab CI/CD 작업 등에서 사용되는 자격 증명을 위한 단일 보안 데이터 저장소를 제공하는 데 활용할 수 있습니다. 인프라의 시스템 및 배포에 SSL/TLS 인증서를 제공하는 방법으로도 사용할 수 있습니다. Vault를 모든 자격 증명의 단일 소스로 활용하면 모든 민감한 자격 증명 및 인증서에 대한 액세스, 제어 및 감사 기능의 단일 소스를 갖춤으로써 더 큰 보안을 얻을 수 있습니다. 이 기능을 사용하려면 GitLab에 최고 수준의 액세스 권한과 제어 권한을 부여해야 합니다. 따라서 GitLab이 손상되면 이 Vault 인스턴스의 보안도 함께 손상됩니다. 이 보안 위험을 방지하려면 GitLab에서는 자체 HashiCorp Vault를 사용하여 [CI와 함께 외부 시크릿](../../../../../ci/secrets/_index.md)을 활용할 것을 권장합니다.

[관리 프로젝트 템플릿](../../../../clusters/management_project_template.md)에서 생성된 프로젝트가 이미 있다고 가정하고, Vault를 설치하려면 `helmfile.yaml`에서 이 줄의 주석을 제거해야 합니다:

```yaml
  - path: applications/vault/helmfile.yaml
```

기본적으로 확장 가능한 스토리지 백엔드가 없는 기본 Vault 설정을 받습니다. 이는 간단한 테스트 및 소규모 배포에는 충분하지만 확장성에 한계가 있으며, 단일 인스턴스 배포이므로 Vault 애플리케이션을 업그레이드하면 가동 중단이 발생합니다.

프로덕션 환경에서 Vault를 최적으로 사용하려면 Vault의 내부 구조와 구성 방법을 충분히 이해하는 것이 좋습니다. 이는 [Vault 구성 가이드](../../../../../ci/secrets/hashicorp_vault.md#configure-your-vault-server), [Vault 문서](https://developer.hashicorp.com/vault/docs/internals) 및 Vault Helm 차트 [`values.yaml` 파일](https://github.com/hashicorp/vault-helm/blob/v0.3.3/values.yaml)을 읽어서 수행할 수 있습니다.

최소한 대부분의 사용자는 다음을 설정합니다:

- 주요 키를 추가로 암호화하기 위한 [시일](https://developer.hashicorp.com/vault/docs/configuration/seal).
- 환경 및 스토리지 보안 요구 사항에 적합한 [스토리지 백엔드](https://developer.hashicorp.com/vault/docs/configuration/storage).
- [HA 모드](https://developer.hashicorp.com/vault/docs/concepts/ha).
- [Vault UI](https://developer.hashicorp.com/vault/docs/configuration/ui).

다음은 Google Key Management Service를 자동 언실(auto-unseal)으로 구성하고, Google Cloud Storage 백엔드를 사용하며, Vault UI를 활성화하고, 3개의 포드 복제본으로 HA를 활성화하는 예제 값 파일(`applications/vault/values.yaml`)입니다. 아래의 `storage` 및 `seal` 섹션은 예제이며 환경에 맞는 설정으로 교체해야 합니다.

```yaml
# Enable the Vault WebUI
ui:
  enabled: true
server:
  # Disable the built in data storage volume as it's not safe for High Availability mode
  dataStorage:
    enabled: false
  # Enable High Availability Mode
  ha:
    enabled: true
    # Configure Vault to listen on port 8200 for normal traffic and port 8201 for inter-cluster traffic
    config: |
      listener "tcp" {
        tls_disable = 1
        address = "[::]:8200"
        cluster_address = "[::]:8201"
      }
      # Configure Vault to store its data in a GCS Bucket backend
      storage "gcs" {
        path = "gcs://my-vault-storage/vault-bucket"
        ha_enabled = "true"
      }
      # Configure Vault to unseal storage using a GKMS key
      seal "gcpckms" {
         project     = "vault-helm-dev-246514"
         region      = "global"
         key_ring    = "vault-helm-unseal-kr"
         crypto_key  = "vault-helm-unseal-key"
      }
```

Vault를 성공적으로 설치한 후에는 [Vault를 초기화](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-deploy#initializing-the-vault)하고 초기 루트 토큰을 획득해야 합니다. 이를 수행하려면 Vault가 배포된 Kubernetes 클러스터에 대한 액세스 권한이 필요합니다. Vault를 초기화하려면 Kubernetes 내에서 실행 중인 Vault 포드 중 하나에 대한 셸을 가져옵니다(일반적으로 `kubectl` 명령줄 도구를 사용하여 수행됨). 포드에 대한 셸을 얻은 후 `vault operator init` 명령을 실행합니다:

```shell
kubectl -n gitlab-managed-apps exec -it vault-0 sh
/ $ vault operator init
```

이것은 언실 키와 초기 루트 토큰을 제공해야 합니다. 전체 수명 주기에 걸쳐 Vault를 언실하는 데 필요하므로 이를 메모해 두고 안전하게 보관해야 합니다.
