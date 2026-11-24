---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Installer cert-manager avec un projet de gestion de cluster
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

En supposant que vous ayez déjà un projet créé à partir d'un [modèle de projet de gestion](../../../../clusters/management_project_template.md), pour installer cert-manager, vous devez décommenter cette ligne dans votre `helmfile.yaml` :

```yaml
  - path: applications/cert-manager/helmfile.yaml
```

Et mettez à jour le `applications/cert-manager/helmfile.yaml` avec une adresse e-mail valide.

```yaml
  values:
    - letsEncryptClusterIssuer:
        #
        # IMPORTANT: This value MUST be set to a valid email.
        #
        email: example@example.com
```

> [!note]
> Si votre version de Kubernetes est antérieure à la version 1.20 et que vous [migrez depuis les applications gérées par GitLab vers un projet de gestion de cluster](../../../../clusters/migrating_from_gma_to_project_template.md), vous pouvez à la place utiliser `- path: applications/cert-manager-legacy/helmfile.yaml` pour prendre en charge une release existante de cert-manager v0.10.

cert-manager :

- Est installé par défaut dans l'espace de nommage `gitlab-managed-apps` de votre cluster.
- Inclut un [Let's Encrypt `ClusterIssuer`](https://cert-manager.io/docs/configuration/acme/) activé par défaut. Dans la release `certmanager-issuer`, l'émetteur requiert une adresse e-mail valide pour `letsEncryptClusterIssuer.email`. Let's Encrypt utilise cette adresse e-mail pour vous contacter à propos des certificats arrivant à expiration et des problèmes liés à votre compte.
- Peut être personnalisé dans `applications/cert-manager/helmfile.yaml` en transmettant des `values` personnalisées à la release `certmanager`. Consultez le [chart](https://github.com/cert-manager/cert-manager) pour connaître les options de configuration disponibles.
