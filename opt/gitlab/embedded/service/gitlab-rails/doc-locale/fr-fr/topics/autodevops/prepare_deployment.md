---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Préparer Auto DevOps pour le déploiement
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Si vous activez Auto DevOps sans définir le domaine de base et la stratégie de déploiement, GitLab ne peut pas déployer votre application directement. Par conséquent, vous devez préparer les stratégies avant d'activer Auto DevOps.

## Stratégie de déploiement {#deployment-strategy}

Lorsque vous utilisez Auto DevOps pour déployer vos applications, choisissez la [stratégie de déploiement continu](../../ci/_index.md) qui correspond le mieux à vos besoins :

| Stratégie de déploiement                                                     | Configuration | Méthodologie |
|-------------------------------------------------------------------------|-------|-------------|
| **Déploiement continu en production**                                 | Active [Auto Deploy](stages.md#auto-deploy) avec la branche par défaut déployée en continu en production. | Déploiement continu en production.|
| **Déploiement continu en production par sorties incrémentielles programmées** | Définit la variable [`INCREMENTAL_ROLLOUT_MODE`](cicd_variables.md#timed-incremental-rollout-to-production) sur `timed`. | Déploiement continu en production avec un délai de 5 minutes entre les déploiements progressifs. |
| **Déploiement automatique pour la préproduction, déploiement manuel pour la production**    | Définit [`STAGING_ENABLED`](cicd_variables.md#deploy-policy-for-staging-and-production-environments) sur `1` et [`INCREMENTAL_ROLLOUT_MODE`](cicd_variables.md#incremental-rollout-to-production) sur `manual`. | La branche par défaut est déployée en continu en préproduction et livrée en continu en production. |

Vous pouvez choisir la méthode de déploiement lors de l'activation d'Auto DevOps ou ultérieurement :

1. Dans GitLab, accédez aux **Paramètres** de votre projet > **CI/CD** > **Auto DevOps**.
1. Choisissez la stratégie de déploiement.
1. Sélectionnez **Enregistrer les modifications**.

> [!note]
> Utilisez la technique de [déploiement bleu/vert](../../ci/environments/incremental_rollouts.md#blue-green-deployment) pour minimiser les interruptions de service et les risques.

## Domaine de base Auto DevOps {#auto-devops-base-domain}

Le domaine de base Auto DevOps est requis pour utiliser les [Auto Review Apps](stages.md#auto-review-apps) et [Auto Deploy](stages.md#auto-deploy).

Pour définir le domaine de base, effectuez l'une des opérations suivantes :

- Dans le projet, le groupe ou l'instance : accédez aux paramètres de votre cluster et ajoutez-le à cet endroit.
- Dans le projet ou le groupe : ajoutez-le en tant que variable d'environnement : `KUBE_INGRESS_BASE_DOMAIN`.
- Dans l'instance : accédez à la zone **Admin**, puis à **Paramètres** > **CI/CD** > **Intégration et livraison continues** et ajoutez-le à cet endroit.

La variable de domaine de base `KUBE_INGRESS_BASE_DOMAIN` suit le même ordre de précédence que les autres [variables](../../ci/variables/_index.md#cicd-variable-precedence) d'environnement.

Si vous ne spécifiez pas le domaine de base dans vos projets et groupes, Auto DevOps utilise le **Domaine Auto DevOps** à l'échelle de l'instance.

Auto DevOps nécessite un enregistrement DNS générique `A` correspondant aux domaines de base. Pour un domaine de base `example.com`, vous aurez besoin d'une entrée DNS de ce type :

```plaintext
*.example.com   3600     A     10.0.2.2
```

Dans ce cas, les applications déployées sont servies depuis `example.com`, et `10.0.2.2` est l'adresse IP de votre répartiteur de charge, généralement NGINX ([voir les prérequis](requirements.md)). La configuration de l'enregistrement DNS dépasse la portée de ce document ; consultez votre fournisseur DNS pour plus d'informations.

Vous pouvez également utiliser des services publics gratuits comme [nip.io](https://nip.io), qui fournissent un DNS générique automatique sans aucune configuration. Pour [nip.io](https://nip.io), définissez le domaine de base Auto DevOps sur `10.0.2.2.nip.io`.

Une fois la configuration terminée, toutes les requêtes atteignent le répartiteur de charge, qui les achemine vers les pods Kubernetes exécutant votre application.
