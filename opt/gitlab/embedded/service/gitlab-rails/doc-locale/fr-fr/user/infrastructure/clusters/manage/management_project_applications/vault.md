---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Installer Vault avec un projet de gestion de cluster
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[HashiCorp Vault](https://www.vaultproject.io/) est une solution de gestion des secrets qui peut être utilisée pour gérer et stocker en toute sécurité des mots de passe, des identifiants, des certificats, et bien plus encore. Une installation de Vault peut être utilisée pour fournir un magasin de données sécurisé unique pour les identifiants utilisés dans vos applications, vos jobs GitLab CI/CD, et bien plus encore. Elle peut également servir à fournir des certificats SSL/TLS aux systèmes et déploiements de votre infrastructure. L'utilisation de Vault comme source unique pour tous ces identifiants permet une sécurité accrue en disposant d'une source unique d'accès, de contrôle et d'auditabilité pour l'ensemble de vos identifiants et certificats sensibles. Cette fonctionnalité nécessite d'accorder à GitLab le niveau d'accès et de contrôle le plus élevé. Par conséquent, si GitLab est compromis, la sécurité de cette instance Vault l'est également. Pour éviter ce risque de sécurité, GitLab recommande d'utiliser votre propre HashiCorp Vault pour tirer parti des [secrets externes avec CI](../../../../../ci/secrets/_index.md).

En supposant que vous disposez déjà d'un projet créé à partir d'un [modèle de projet de gestion](../../../../clusters/management_project_template.md), pour installer Vault, vous devez décommenter cette ligne dans votre `helmfile.yaml` :

```yaml
  - path: applications/vault/helmfile.yaml
```

Par défaut, vous obtenez une configuration Vault de base sans backend de stockage évolutif. Cela est suffisant pour des tests simples et des déploiements à petite échelle, mais présente des limites en termes de mise à l'échelle, et comme il s'agit d'un déploiement sur une instance unique, la mise à niveau de l'application Vault entraîne des interruptions de service.

Pour utiliser Vault de manière optimale dans un environnement de production, il est idéal d'avoir une bonne compréhension du fonctionnement interne de Vault et de la manière de le configurer. Pour ce faire, consultez le [guide de configuration de Vault](../../../../../ci/secrets/hashicorp_vault.md#configure-your-vault-server), la [documentation de Vault](https://developer.hashicorp.com/vault/docs/internals) et le fichier [`values.yaml` du chart Helm de Vault](https://github.com/hashicorp/vault-helm/blob/v0.3.3/values.yaml).

Au minimum, la plupart des utilisateurs configurent :

- Un [seal](https://developer.hashicorp.com/vault/docs/configuration/seal) pour le chiffrement supplémentaire de la clé principale.
- Un [backend de stockage](https://developer.hashicorp.com/vault/docs/configuration/storage) adapté aux exigences de l'environnement et de la sécurité du stockage.
- Le [mode HA](https://developer.hashicorp.com/vault/docs/concepts/ha).
- L'[interface utilisateur de Vault](https://developer.hashicorp.com/vault/docs/configuration/ui).

Voici un exemple de fichier de valeurs (`applications/vault/values.yaml`) qui configure Google Key Management Service pour le déverrouillage automatique (auto-unseal), en utilisant un backend Google Cloud Storage, en activant l'interface utilisateur de Vault et en activant le mode HA avec 3 réplicas de pods. Les stanzas `storage` et `seal` ci-dessous sont des exemples et doivent être remplacés par des paramètres spécifiques à votre environnement.

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

Une fois Vault installé avec succès, vous devez [initialiser Vault](https://developer.hashicorp.com/vault/tutorials/getting-started/getting-started-deploy#initializing-the-vault) et obtenir le jeton root initial. Pour ce faire, vous devez avoir accès à votre cluster Kubernetes dans lequel Vault a été déployé. Pour initialiser Vault, ouvrez un shell vers l'un des pods Vault s'exécutant dans Kubernetes (cette opération est généralement effectuée à l'aide de l'outil en ligne de commande `kubectl`). Une fois que vous avez un shell dans le pod, exécutez la commande `vault operator init` :

```shell
kubectl -n gitlab-managed-apps exec -it vault-0 sh
/ $ vault operator init
```

Cela devrait vous fournir vos clés de déverrouillage (unseal keys) et votre jeton root initial. Veillez à les noter et à les conserver en lieu sûr, car ils sont nécessaires pour déverrouiller Vault tout au long de son cycle de vie.
