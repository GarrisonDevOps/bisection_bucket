---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Pour accélérer la création de projets dans votre groupe, créez des modèles de projets personnalisés et partagez-les avec votre groupe."
title: Modèles de projets personnalisés pour les groupes
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Le sélecteur de groupe permettant de parcourir les modèles de groupe en dehors d'un contexte de groupe a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/590012) dans GitLab 18.11 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `constrain_group_project_templates`. Fonctionnalité désactivée par défaut.
- Le sélecteur de groupe permettant de parcourir les modèles de groupe en dehors d'un contexte de groupe est [disponible de manière générale](https://gitlab.com/gitlab-org/gitlab/-/issues/586332) dans GitLab 19.0. Le feature flag `constrain_group_project_templates` a été supprimé.

{{< /history >}}

Lorsque vous créez un projet, vous pouvez [choisir dans une liste de modèles](../project/_index.md). Ces modèles, pour des éléments tels que GitLab Pages ou Ruby, renseignent le nouveau projet avec une copie des fichiers contenus dans le modèle. Ces informations sont identiques à celles utilisées par [l'import/export de projets GitLab](../project/settings/import_export.md) et peuvent vous aider à démarrer un nouveau projet plus rapidement.

Vous pouvez [personnaliser la liste](../project/_index.md) des modèles disponibles, afin que tous les projets de votre groupe disposent de la même liste. Pour ce faire, vous renseignez un sous-groupe avec les projets que vous souhaitez utiliser comme modèles.

Vous pouvez également configurer des [modèles personnalisés pour l'instance](../../administration/project_templates.md).

## Configurer des modèles de projets pour un groupe {#set-up-project-templates-for-a-group}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

Pour configurer des modèles de projets personnalisés dans un groupe, ajoutez le sous-groupe contenant les modèles de projets aux paramètres du groupe :

1. Dans le groupe, créez un [sous-groupe](subgroups/_index.md).
1. [Ajoutez des projets au nouveau sous-groupe](_index.md#add-projects-to-a-group) en tant que modèles.
1. Dans le menu de gauche du groupe, sélectionnez **Paramètres** > **Général**.
1. Développez **Modèles de projets personnalisés** et sélectionnez le sous-groupe.

La prochaine fois qu'un membre du groupe crée un projet, il peut sélectionner n'importe lequel des projets du sous-groupe.

Les projets des sous-groupes imbriqués ne sont pas inclus dans la liste des modèles.

## Quels projets sont disponibles en tant que modèles {#which-projects-are-available-as-templates}

- Les projets publics et internes peuvent être sélectionnés par tout utilisateur authentifié comme modèle pour un nouveau projet, si toutes les [fonctionnalités du projet](../project/settings/_index.md#configure-project-features-and-permissions) à l'exception de **GitLab Pages** et de **Sécurité et conformité** sont définies sur **Toute personne ayant accès**.
- Les projets privés ne peuvent être sélectionnés que par les utilisateurs qui sont membres des projets.

Lorsque vous créez un projet en dehors d'un contexte de groupe, vous devez sélectionner un groupe dans la liste déroulante avant de pouvoir parcourir ses modèles. Seuls les groupes auxquels vous avez accès sont répertoriés.

## Exemple de structure {#example-structure}

Voici un exemple de structure de groupe et de projet pour les modèles de projets, pour `myorganization` :

```plaintext
# GitLab instance and group
gitlab.com/myorganization/
    # Subgroups
    internal
    tools
    # Subgroup for handling project templates
    websites
        templates
            # Project templates
            client-site-django
            client-site-gatsby
            client-site-html

        # Other projects
        client-site-a
        client-site-b
        client-site-c
        ...
```

## Ce qui est copié depuis les modèles {#what-is-copied-from-the-templates}

Lorsque vous créez un projet à partir d'un modèle, tous les éléments de projet exportables sont copiés depuis le modèle vers le nouveau projet. Ces éléments comprennent :

- Branches, commits et tags du dépôt.
- Fichiers téléversés dans le projet.
- Configuration du projet.
- Tickets et merge requests avec leurs commentaires et autres métadonnées.
- Labels, jalons, snippets et releases.
- Configuration du pipeline CI/CD.

Pour obtenir la liste complète des éléments copiés, consultez [les éléments de projet qui sont exportés](../project/settings/import_export.md#project-items-that-are-exported).

### Autorisations et données sensibles {#permissions-and-sensitive-data}

Le comportement de copie varie en fonction de vos autorisations :

- Si vous êtes administrateur GitLab, tous les paramètres du projet, y compris les membres du projet, sont copiés dans le nouveau projet.
- Si vous disposez du rôle Propriétaire pour le projet contenant les modèles personnalisés de l'instance, mais que vous n'êtes pas administrateur GitLab : les paramètres du projet sont copiés, mais pas les membres du projet.
- Si vous ne disposez pas du rôle Propriétaire pour le projet et que vous n'êtes pas administrateur GitLab : les clés de déploiement et les webhooks du projet ne sont pas copiés, car ils contiennent des données sensibles.

Les niveaux d'accès aux branches et tags protégés sont également affectés lors de la copie des modèles :

- Si vous disposez du rôle Propriétaire pour le groupe principal du nouveau projet, ou si vous êtes administrateur GitLab, ces niveaux d'accès sont copiés dans le nouveau projet.
- Dans le cas contraire, les niveaux d'accès aux branches et tags protégés sont réinitialisés sur Mainteneurs. Les niveaux d'accès définis sur Personne sont préservés. Pour plus d'informations, consultez [les modifications apportées aux éléments importés](../project/settings/import_export.md#changes-to-imported-items).

Les clés de déploiement et les webhooks contiennent des secrets sensibles. Ils ne sont copiés que lorsque l'identité qui crée le projet dispose du rôle Propriétaire sur le projet modèle ou d'un accès administrateur. Lorsque vous créez un projet à partir d'un modèle en utilisant l'API, cette identité dépend du jeton :

- Jeton d'accès personnel : utilise les autorisations du propriétaire du jeton. Les clés de déploiement et les webhooks sont copiés si cet utilisateur dispose du rôle Propriétaire sur le projet modèle ou s'il est administrateur.
- Jeton d'accès de groupe ou jeton d'accès au projet : agit en tant qu'[utilisateur bot](settings/group_access_tokens.md#bot-users-for-groups). L'utilisateur bot est membre uniquement du groupe ou du projet dans lequel vous créez le jeton. Si cette portée n'inclut pas le projet modèle, l'utilisateur bot ne dispose pas du rôle Propriétaire sur le projet modèle, et les clés de déploiement et les webhooks ne sont pas copiés. Pour les copier, utilisez un jeton d'accès personnel d'un utilisateur disposant du rôle Propriétaire sur le projet modèle.

## Attributions d'utilisateurs dans les modèles {#user-assignments-in-templates}

Lorsque vous utilisez un modèle créé par un autre utilisateur, tous les éléments qui étaient attribués à un utilisateur dans le modèle vous sont réattribués. Il est important de comprendre cette réattribution lorsque vous configurez des fonctionnalités de sécurité telles que les branches et les tags protégés. Par exemple, si le modèle contient une branche protégée :

- Dans le modèle, la branche autorise le propriétaire du modèle à effectuer des merges dans la branche par défaut.
- Dans le projet créé à partir du modèle, la branche vous autorise à effectuer des merges dans la branche par défaut.

Les niveaux d'accès aux branches et tags protégés sont également affectés lors de la copie des modèles. Pour plus d'informations, consultez [les autorisations et données sensibles](#permissions-and-sensitive-data).

## Dépannage {#troubleshooting}

### L'administrateur ne peut pas voir les modèles de projets personnalisés du groupe lors de la création d'un projet {#administrator-cannot-see-custom-project-templates-for-the-group-when-creating-a-project}

Les modèles de projets personnalisés d'un groupe sont disponibles uniquement pour les membres du groupe. Si le compte administrateur que vous utilisez n'est pas membre d'un groupe, vous ne pouvez pas accéder aux modèles.
