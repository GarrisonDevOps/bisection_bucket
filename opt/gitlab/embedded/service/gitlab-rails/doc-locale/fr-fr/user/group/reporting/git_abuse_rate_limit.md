---
stage: Software Supply Chain Security
group: Authorization
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Limite de débit pour les abus Git
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/epics/8066) dans GitLab 15.2 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `limit_unique_project_downloads_per_namespace_user`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/365724) dans GitLab 15.6.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/183101) dans GitLab 18.0. Suppression du feature flag `limit_unique_project_downloads_per_namespace_user`.

{{< /history >}}

Il s'agit de la documentation au niveau du groupe. Pour les instances GitLab Self-Managed, consultez la [documentation d'administration](../../../administration/reporting/git_abuse_rate_limit.md).

La limitation de débit pour les abus Git est une fonctionnalité qui bannit automatiquement les utilisateurs et utilisatrices qui téléchargent, clonent, tirent (pull), récupèrent (fetch) ou dupliquent plus d'un nombre spécifié de dépôts d'un groupe dans un délai donné. Les utilisateurs et utilisatrices bannis ne peuvent pas accéder au groupe principal ni à aucun de ses sous-groupes non publics via HTTP ou SSH. La limite de débit s'applique également aux utilisateurs et utilisatrices qui s'authentifient avec des [jetons d'accès personnels](../../profile/personal_access_tokens.md) ou des [jetons d'accès de groupe](../settings/group_access_tokens.md), ainsi que des [jetons de job CI/CD](../../../ci/jobs/ci_job_token.md). L'accès aux groupes sans lien n'est pas affecté.

La limitation de débit pour les abus Git ne s'applique pas aux propriétaires du groupe principal, aux [jetons de déploiement](../../project/deploy_tokens/_index.md) ni aux [clés de déploiement](../../project/deploy_keys/_index.md).

## Notifications de bannissement automatique {#automatic-ban-notifications}

Les utilisateurs et utilisatrices sélectionnés reçoivent une notification par e-mail lorsqu'un utilisateur ou une utilisatrice est banni(e).

Si le bannissement automatique est désactivé, un utilisateur ou une utilisatrice n'est pas banni(e) automatiquement lorsqu'il ou elle dépasse la limite. Cependant, les notifications sont tout de même envoyées. Vous pouvez utiliser cette configuration pour déterminer les valeurs correctes des paramètres de limite de débit avant d'activer le bannissement automatique.

Si le bannissement automatique est activé, une notification par e-mail est envoyée lorsqu'un utilisateur ou une utilisatrice est sur le point d'être banni(e), et il ou elle est automatiquement banni(e) du groupe et de ses sous-groupes.

## Configurer la limitation de débit pour les abus Git {#configure-git-abuse-rate-limiting}

1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Rapports**.
1. Mettez à jour les paramètres de limite de débit pour les abus Git :
   1. Saisissez un nombre dans le champ **Nombre de dépôts**, supérieur ou égal à `0` et inférieur ou égal à `10,000`. Ce nombre spécifie le nombre maximal de dépôts uniques qu'un utilisateur ou une utilisatrice peut télécharger dans la période définie avant d'être banni(e). Lorsqu'il est défini sur `0`, la limitation de débit pour les abus Git est désactivée.
   1. Saisissez un nombre dans le champ **Durée considérée (secondes)**, supérieur ou égal à `0` et inférieur ou égal à `86,400` (10 jours). Ce nombre spécifie le temps en secondes pendant lequel un utilisateur ou une utilisatrice peut télécharger le nombre maximal de dépôts avant d'être banni(e). Lorsqu'il est défini sur `0`, la limitation de débit pour les abus Git est désactivée.
   1. Facultatif. Excluez jusqu'à `100` utilisateurs et utilisatrices en les ajoutant au champ **Utilisateurs et utilisatrices exclus**. Les utilisateurs et utilisatrices exclus ne sont pas automatiquement bannis.
   1. Ajoutez jusqu'à `100` utilisateurs et utilisatrices dans le champ **Envoyer des notifications à**. Vous devez sélectionner au moins un utilisateur ou une utilisatrice. Tous les utilisateurs et utilisatrices ayant le rôle Propriétaire pour le groupe principal sont sélectionnés par défaut.
   1. Facultatif. Activez le bouton bascule **Bannir automatiquement les utilisateurs et utilisatrices de cet espace de nommage lorsqu'ils dépassent les limites spécifiées** pour activer le bannissement automatique.
1. Sélectionnez **Enregistrer les modifications**.

## Sujets connexes {#related-topics}

- [Bannir et débannir des utilisateurs et utilisatrices](../moderate_users.md).
