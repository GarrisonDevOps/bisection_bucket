---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Limites de requêtes API des organisations
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/470613) dans GitLab 17.5 avec le [feature flag](../../administration/feature_flags/_index.md) `allow_organization_creation`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../policy/development_stages_support.md).
- [Modification](https://gitlab.com/gitlab-org/gitlab/-/issues/549062) dans GitLab 18.4. Le feature flag `allow_organization_creation` a été consolidé et renommé en `organization_switching`.
- Le feature flag a été [modifié](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249678) en `org_stage_experimental` dans GitLab 19.4. Fonctionnalité désactivée par défaut. Le feature flag `organization_switching` a été supprimé.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Les requêtes dépassant la limite de débit sont enregistrées dans le fichier `auth.log`.

Par exemple, si vous définissez une limite de 400 pour `POST /organizations`, les requêtes vers le point de terminaison d'API qui dépassent un débit de 400 en une minute sont bloquées. L'accès au point de terminaison est rétabli après une minute.

Vous pouvez configurer la limite de débit par minute et par utilisateur pour les requêtes vers l'[API POST /organizations](../../api/organizations.md#create-an-organization). La valeur par défaut est 10.

## Modifier la limite de débit {#change-the-rate-limit}

Prérequis :

- Disposer d'un accès administrateur.

Pour modifier la limite de débit :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Réseau**.
1. Développez **Limites de requêtes API des organisations**.
1. Modifiez la valeur de n'importe quelle limite de débit. Les limites de débit sont définies par minute et par utilisateur. Pour désactiver une limite de débit, définissez la valeur sur `0`.
1. Sélectionnez **Enregistrer les modifications**.
