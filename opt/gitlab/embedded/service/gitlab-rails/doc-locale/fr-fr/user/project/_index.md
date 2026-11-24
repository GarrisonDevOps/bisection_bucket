---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Créer un projet
description: Nouveau projet et modèles de projet.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous disposez de différentes options pour créer un projet. Vous pouvez créer un projet vide, créer un projet à partir de modèles intégrés ou personnalisés, ou [créer un projet avec `git push`](../../topics/git/project.md).

## Créer un projet vide {#create-a-blank-project}

Pour créer un projet vide :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer un projet vide**.
1. Saisissez les détails du projet :
   1. **Nom du projet** : saisissez le nom de votre projet. Pour plus d'informations, consultez les [règles de nommage](../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs).
   1. **Identifiant « slug » du projet** : saisissez le chemin vers votre projet. GitLab utilise le slug comme chemin d'URL.
   1. **Cible du déploiement du projet (facultatif)** : si vous souhaitez déployer votre projet dans un environnement spécifique, sélectionnez la cible de déploiement appropriée.
   1. **Niveau de visibilité** : sélectionnez le niveau de visibilité approprié. Consultez les [droits d'affichage et d'accès](../public_access.md) pour les utilisateurs.
   1. **Initialiser le dépôt avec un README** : sélectionnez cette option pour initialiser le dépôt Git, créer une branche par défaut et activer le clonage du dépôt de ce projet.
   1. **Activer les tests statiques de sécurité des applications (SAST)** : sélectionnez cette option pour analyser le code source à la recherche de vulnérabilités de sécurité connues.
   1. **Activer la détection de secret** : sélectionnez cette option pour analyser le code source à la recherche de secrets et d'identifiants afin de prévenir tout accès non autorisé.
1. Sélectionnez **Créer le projet**.

## Créer un projet à partir d'un modèle intégré {#create-a-project-from-a-built-in-template}

Les modèles intégrés remplissent un nouveau projet avec des fichiers pour vous aider à démarrer. Ces modèles proviennent des groupes [`project-templates`](https://gitlab.com/gitlab-org/project-templates) et [`pages`](https://gitlab.com/pages). Tout le monde peut contribuer aux modèles de projet intégrés.

Les administrateurs et les propriétaires de groupe peuvent [contrôler la disponibilité des modèles intégrés](../group/manage.md#control-built-in-project-templates) lors de la création de projets.

Pour créer un projet à partir d'un modèle intégré :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer à partir d'un modèle**.
1. Sélectionnez l'onglet **Intégré**.
1. Dans la liste des modèles :
   - Pour prévisualiser un modèle, sélectionnez **Aperçu**.
   - Pour utiliser un modèle, sélectionnez **Utiliser un modèle**.
1. Saisissez les détails du projet :
   - **Nom du projet** : saisissez le nom de votre projet.
   - **Identifiant « slug » du projet** : saisissez le chemin vers votre projet. GitLab utilise le slug comme chemin d'URL.
   - **Description du projet (facultative)** Saisissez une description pour votre projet. La limite est de 500 caractères.
   - **Niveau de visibilité** : sélectionnez le niveau de visibilité approprié. Consultez les [droits d'affichage et d'accès](../public_access.md) pour les utilisateurs.
1. Sélectionnez **Créer le projet**.

> [!note]
> Si un utilisateur crée un projet à partir d'un modèle ou [importe un projet](settings/import_export.md#import-a-project-and-its-data), il apparaît comme l'auteur des éléments importés, qui conservent l'horodatage d'origine du modèle ou de l'importation. Cela peut faire apparaître des éléments comme s'ils avaient été créés avant que le compte de l'utilisateur n'existe.

Les objets importés sont étiquetés comme `By <username> on <timestamp>`. Avant GitLab 17.1, le label était suffixé par `(imported from GitLab)`.

### Créer un projet à partir du modèle Protocole d'audit HIPAA {#create-a-project-from-the-hipaa-audit-protocol-template}

Le modèle Protocole d'audit HIPAA contient des tickets pour les demandes d'audit figurant dans le Protocole d'audit HIPAA publié par le Département américain de la Santé et des Services sociaux.

Pour créer un projet à partir du modèle Protocole d'audit HIPAA :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer à partir d'un modèle**.
1. Sélectionnez l'onglet **Intégré**.
1. Recherchez le modèle **Protocole d'audit HIPAA** :
   - Pour prévisualiser le modèle, sélectionnez **Aperçu**.
   - Pour utiliser le modèle, sélectionnez **Utiliser un modèle**.
1. Saisissez les détails du projet :
   - **Nom du projet** : saisissez le nom de votre projet.
   - **Identifiant « slug » du projet** : saisissez le chemin vers votre projet. GitLab utilise le slug comme chemin d'URL.
   - **Description du projet (facultative)** Saisissez une description pour votre projet. La limite est de 500 caractères.
   - **Niveau de visibilité** : sélectionnez le niveau de visibilité approprié. Consultez les [droits d'affichage et d'accès](../public_access.md) pour les utilisateurs.
1. Sélectionnez **Créer le projet**.

## Créer un projet à partir d'un modèle personnalisé {#create-a-project-from-a-custom-template}

{{< history >}}

- Le sélecteur de groupe pour parcourir les modèles de groupe en dehors d'un contexte de groupe a été [introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/590012) dans GitLab 18.11 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `constrain_group_project_templates`. Fonctionnalité désactivée par défaut.
- Le sélecteur de groupe pour parcourir les modèles de groupe en dehors d'un contexte de groupe est [disponible en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/586332) dans GitLab 19.0. Le feature flag `constrain_group_project_templates` a été supprimé.

{{< /history >}}

Les modèles de projet personnalisés sont disponibles pour votre [instance](../../administration/project_templates.md) et votre [groupe](../group/custom_project_templates.md).

Pour créer un projet à partir d'un modèle personnalisé :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer à partir d'un modèle**.
1. Sélectionnez l'onglet **Instance** ou **Groupe**.
   - Dans l'onglet **Groupe**, si vous n'êtes pas dans un contexte de groupe et qu'aucun groupe n'est présélectionné, une liste déroulante de groupes s'affiche. Sélectionnez un groupe pour charger ses modèles.
1. Dans la liste des modèles :
   - Pour prévisualiser le modèle, sélectionnez **Aperçu**.
   - Pour utiliser un modèle, sélectionnez **Utiliser un modèle**.
1. Saisissez les détails du projet :
   - **Nom du projet** : saisissez le nom de votre projet.
   - **Identifiant « slug » du projet** : saisissez le chemin vers votre projet. GitLab utilise le slug comme chemin d'URL.
   - **Description du projet (facultative)** Saisissez une description pour votre projet. La limite est de 500 caractères.
   - **Niveau de visibilité** : sélectionnez le niveau de visibilité approprié. Consultez les [droits d'affichage et d'accès](../public_access.md) pour les utilisateurs.
1. Sélectionnez **Créer le projet**.

## Créer un projet utilisant le hachage SHA-256 {#create-a-project-that-uses-sha-256-hashing}

{{< details >}}

- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/431864) dans GitLab 16.7 [avec le feature flag](../../administration/feature_flags/_index.md) `support_sha256_repositories`. Fonctionnalité désactivée par défaut. Cette fonctionnalité est une [version expérimentale](../../policy/development_stages_support.md#experiment).

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

Vous ne pouvez sélectionner le hachage SHA-256 pour un projet qu'au moment de sa création. Git ne prend pas en charge la migration vers SHA-256 ultérieurement, ni le retour à SHA-1.

Pour créer un projet utilisant le hachage SHA-256 :

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Saisissez les détails du projet :
   - **Nom du projet** : saisissez le nom de votre projet.
   - **Identifiant « slug » du projet** : saisissez le chemin vers votre projet. GitLab utilise le slug comme chemin d'URL.
   - **Description du projet (facultative)** Saisissez une description pour votre projet. La limite est de 500 caractères.
   - **Niveau de visibilité** : sélectionnez le niveau de visibilité approprié. Consultez les [droits d'affichage et d'accès](../public_access.md) pour les utilisateurs.
1. Dans la zone **Configuration du Projet**, développez les **Paramètres expérimentaux**.
1. Sélectionnez **Utiliser SHA-256 comme algorithme de hachage du dépôt**.
1. Sélectionnez **Créer le projet**.

### Pourquoi SHA-256 ? {#why-sha-256}

Par défaut, Git utilise l'algorithme de hachage SHA-1 pour générer un identifiant de 40 caractères pour des objets tels que les commits, les blobs, les arbres et les tags. La vulnérabilité de l'algorithme SHA-1 a été démontrée lorsque [Google a réussi à produire une collision de hachage](https://security.googleblog.com/2017/02/announcing-first-sha1-collision.html). Le projet Git n'est pas encore affecté par ce type d'attaques en raison de la façon dont Git stocke les objets.

Dans les dépôts SHA-256, l'algorithme génère un identifiant de 64 caractères au lieu de 40 caractères. Le projet Git a déterminé que la fonctionnalité SHA-256 était sûre à utiliser lorsqu'il a [supprimé le label expérimental](https://github.com/git/git/blob/master/Documentation/RelNotes/2.42.0.txt#L41-L45).

Les réglementations fédérales, telles que les [directives](https://csrc.nist.gov/projects/hash-functions/nist-policy-on-hash-functions) du NIST et de la CISA, que [FedRamp](https://www.fedramp.gov/) applique, ont fixé une échéance en 2030 pour cesser d'utiliser SHA-1 et encouragent les agences à s'éloigner de SHA-1 dès que possible.

## Sujets connexes {#related-topics}

- [Créer un projet avec `git push`](../../topics/git/project.md)
- [Noms de projets et de groupes réservés](../reserved_names.md)
- [Règles pour les noms de projet et de groupe](../reserved_names.md#rules-for-usernames-project-and-group-names-and-slugs)
- [Gérer les projets](working_with_projects.md)
