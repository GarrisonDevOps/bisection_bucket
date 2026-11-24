---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "Commits signés depuis l'interface utilisateur de GitLab"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Affichage du badge **Vérifié** pour les commits signés de l'interface utilisateur GitLab [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/124218) dans GitLab 16.3 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `gitaly_gpg_signing`. Fonctionnalité désactivée par défaut.
- Vérification des signatures à l'aide de plusieurs clés spécifiées dans l'option `rotated_signing_keys` [introduite](https://gitlab.com/gitlab-org/gitaly/-/merge_requests/6163) dans GitLab 16.3.
- Le feature flag `gitaly_gpg_signing` [activé par défaut](https://gitlab.com/gitlab-org/gitaly/-/merge_requests/6876) sur GitLab Self-Managed et GitLab Dedicated dans GitLab 17.0.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

Lorsque vous créez un commit via l'interface utilisateur de GitLab, le commit n'est pas poussé directement par vous. À la place, le commit est créé en votre nom.

Pour signer ces commits, GitLab utilise une clé globale configurée pour l'instance. Comme GitLab n'a pas accès à votre clé privée, le commit créé ne peut pas être signé à l'aide de la clé associée à votre compte.

> [!note]
> Les commits signés avec une signature vérifiée par GitLab peuvent également apparaître lors d'opérations de [mise en miroir de dépôt](../mirror/_index.md). Dans les deux cas, Gitaly signe cryptographiquement le commit à l'aide de la clé de signature configurée pour l'instance.

Par exemple, si l'utilisateur A applique des [suggestions](../../merge_requests/reviews/suggestions.md) rédigées par l'utilisateur B, le commit contient les éléments suivants :

```plaintext
Author: User A <a@example.com>
Committer: GitLab <noreply@gitlab.com>

Co-authored-by: User B <b@example.com>
```

## Prérequis {#prerequisites}

Avant de pouvoir utiliser la signature de commit pour les commits de l'interface utilisateur GitLab, vous devez [le configurer](../../../../administration/gitaly/configure_gitaly.md#configure-commit-signing-for-gitlab-ui-commits).

## Activer la signature de commit basée sur le web pour un groupe ou un projet {#turn-on-web-based-commit-signing-for-a-group-or-project}

{{< details >}}

Offre : GitLab.com

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200425) dans GitLab 18.3 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `configure_web_based_commit_signing`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/542975) dans GitLab 18.9.
- [Disponible en général](https://gitlab.com/gitlab-org/gitlab/-/issues/542975) dans GitLab 18.10. Le feature flag `configure_web_based_commit_signing` a été supprimé.

{{< /history >}}

Vous pouvez activer la signature de commit basée sur le web pour tous les projets d'un groupe, ou pour un projet individuel.

Lorsque la signature de commit basée sur le web est activée, tous les commits effectués via l'interface utilisateur GitLab (éditeur web, IDE web et merge requests) sont automatiquement signés avec la clé de signature configurée pour l'instance.

### Pour un groupe {#for-a-group}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

Pour activer la signature de commit basée sur le web pour tous les projets d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Général**.
1. Cochez la case **Signer les commits basés sur le web**.

Les projets du groupe héritent de ce paramètre.

### Pour un projet {#for-a-project}

Prérequis :

- Vous devez avoir le rôle Maintainer ou Owner pour le projet.

> [!note]
> Le projet ne doit pas appartenir à un groupe pour lequel la signature de commit basée sur le web est déjà activée. Si le paramètre du groupe est activé, la case à cocher du projet n'est pas disponible.

Pour activer la signature de commit basée sur le web pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Général**.
1. Cochez la case **Signer les commits basés sur le web**.

## Champ Committer des commits {#committer-field-of-the-commits}

Dans Git, les commits ont à la fois un auteur et un committer. Pour les commits web, le champ `Committer` est configurable. Pour mettre à jour ce champ, consultez [configurer la signature de commit pour les commits de l'interface utilisateur GitLab](../../../../administration/gitaly/configure_gitaly.md#configure-commit-signing-for-gitlab-ui-commits).

GitLab propose plusieurs fonctionnalités de sécurité qui reposent sur le champ `Committer` défini sur l'utilisateur qui crée le commit. Par exemple :

- [Règles push](../push_rules.md) : (`Reject unverified users` ou `Commit author's email`).
- [Prévention de l'approbation des merge requests](../../merge_requests/approvals/settings.md#prevent-approvals-by-users-who-add-commits).

Pour les commits signés par l'instance, le champ `Committer` contient une adresse e-mail d'instance. La règle push `Commit author's email` vérifie donc le champ `Author` à la place. La règle push `Reject unverified users` vérifie le champ `Author` pour les commits créés dans l'interface utilisateur GitLab. Pour les commits signés qui arrivent sous forme de push Git standard, par exemple depuis un [miroir push](../mirror/push.md), GitLab ignore cette règle.

## Commits créés à l'aide de l'API REST {#commits-created-using-rest-api}

Les [commits créés à l'aide de l'API REST](../../../../api/commits.md#create-a-commit) sont également considérés comme des commits basés sur le web. En utilisant le point de terminaison de l'API REST, vous pouvez définir les champs `author_name` et `author_email` du commit, ce qui permet de créer des commits au nom d'autres utilisateurs.

Lorsque la signature de commit est activée, les commits créés à l'aide de l'API REST dont les champs `author_name` et `author_email` diffèrent de ceux de l'utilisateur qui envoie la requête API sont rejetés.

## Dépannage {#troubleshooting}

### Les commits web deviennent non signés après un rebase {#web-commits-become-unsigned-after-rebase}

Les commits précédemment signés dans une branche deviennent non signés lorsque :

- La signature de commit est configurée pour les commits créés depuis l'interface utilisateur GitLab.
- La merge request est rebasée depuis l'interface utilisateur GitLab.

Cela se produit parce que les commits précédents sont modifiés et ajoutés au-dessus de la branche cible. GitLab ne peut pas signer ces commits.

Pour contourner ce problème, rebasez la branche localement et poussez les modifications vers GitLab.
