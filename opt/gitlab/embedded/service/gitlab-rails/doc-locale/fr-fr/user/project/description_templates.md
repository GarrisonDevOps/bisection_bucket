---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Modèles de description
description: "Modèles de tickets, modèles de merge requests, modèles d'instance et de groupe."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Prise en charge des éléments de travail](https://gitlab.com/gitlab-org/gitlab/-/issues/512208) introduite dans GitLab 17.10.
- La prise en charge des epics a été [introduite](https://gitlab.com/groups/gitlab-org/-/epics/16088) dans GitLab 17.10 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `work_item_epics`. Activés par défaut. Introduite en [version bêta](../../policy/development_stages_support.md#beta).
- La prise en charge des epics est [généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/468310) dans GitLab 18.1. Le feature flag `work_item_epics` a été supprimé.

{{< /history >}}

Les modèles de description standardisent et automatisent la façon dont les tickets et les merge requests sont créés dans GitLab.

Les modèles de description :

- Créent des mises en page cohérentes pour les tickets et les merge requests dans l'ensemble des projets.
- Fournissent des modèles spécialisés adaptés aux différentes étapes et finalités des workflows.
- Prennent en charge des modèles personnalisés pour les projets, les groupes et l'ensemble de l'instance.
- Remplissent automatiquement les champs avec des variables et des actions rapides.
- Assurent un suivi approprié des bugs, des fonctionnalités et des autres éléments de travail.
- Mettent en forme les [réponses par e-mail du Service Desk](service_desk/configure.md#use-a-custom-template-for-service-desk-tickets).

Vous pouvez définir des modèles à utiliser comme descriptions pour vos :

- [Les tickets](issues/_index.md)
- [Epics](../group/epics/_index.md) (nécessite des [modèles de description au niveau du groupe](#set-group-level-description-templates))
- [Tâches](../tasks.md)
- [OKR](../okrs.md)
- [Incidents](../../operations/incident_management/manage_incidents.md)
- [Tickets du Service Desk](service_desk/_index.md)
- [Les merge requests](merge_requests/_index.md)

Les projets héritent des modèles de leur groupe et de leur instance.

Les modèles doivent :

- Être enregistrés avec l'extension `.md`.
- Être stockés dans le dépôt de votre projet dans le répertoire `.gitlab/issue_templates` ou `.gitlab/merge_request_templates`.
- Être présents sur la branche par défaut.

## Créer un modèle de description {#create-a-description-template}

Créez un nouveau modèle de description sous la forme d'un fichier Markdown (`.md`) dans le répertoire `.gitlab/issue_templates/` de votre dépôt.

Pour créer un modèle de description d'élément de travail :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. À côté de la branche par défaut, sélectionnez {{< icon name="plus" >}}.
1. Sélectionnez **Nouveau fichier**.
1. À côté de la branche par défaut, dans la zone de texte **Nom du fichier**, saisissez `.gitlab/issue_templates/mytemplate.md`, où `mytemplate` est le nom de votre modèle.
1. Effectuez un commit sur votre branche par défaut.

Pour vérifier que cette opération a fonctionné correctement :

1. [Créez un nouveau ticket](issues/create_issues.md) ou [créez un nouvel epic](../group/epics/manage_epics.md#create-an-epic).
1. Vérifiez que vous pouvez trouver votre modèle de description dans la liste déroulante **Choisissez un modèle**.

## Créer un modèle de merge request {#create-a-merge-request-template}

De même que pour les modèles de tickets, créez un nouveau fichier Markdown (`.md`) dans le répertoire `.gitlab/merge_request_templates/` de votre dépôt. Contrairement aux modèles de tickets, les merge requests disposent de règles d'héritage supplémentaires qui dépendent du contenu des messages de commit et des noms de branche. Pour plus d'informations, voir [Création de merge requests](merge_requests/creating_merge_requests.md).

Pour créer un modèle de description de merge request pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. À côté de la branche par défaut, sélectionnez {{< icon name="plus" >}}.
1. Sélectionnez **Nouveau fichier**.
1. À côté de la branche par défaut, dans la zone de texte **Nom du fichier**, saisissez `.gitlab/merge_request_templates/mytemplate.md`, où `mytemplate` est le nom de votre modèle de merge request.
1. Effectuez un commit sur votre branche par défaut.

Pour vérifier que cette opération a fonctionné correctement, [créez une nouvelle merge request](merge_requests/creating_merge_requests.md) et vérifiez que vous pouvez trouver votre modèle de description dans la liste déroulante **Choisissez un modèle**.

## Utiliser les modèles {#use-the-templates}

Lorsque vous créez ou modifiez un ticket ou une merge request, celui-ci s'affiche dans la liste déroulante **Choisissez un modèle**.

Pour appliquer un modèle :

1. Créez ou modifiez un ticket, un élément de travail ou une merge request.
1. Sélectionnez la liste déroulante **Choisissez un modèle**.
1. Si la zone de texte **Description** n'est pas vide, sélectionnez **Appliquer le modèle** pour confirmer.
1. Sélectionnez **Enregistrer les modifications**.

Lorsque vous sélectionnez un modèle de description, son contenu est copié dans la zone de texte de description.

Pour ignorer les modifications apportées à la description après avoir sélectionné le modèle : développez la liste déroulante **Choisissez un modèle** et sélectionnez **Réinitialiser le modèle**.

![Sélection d'un modèle de description dans un ticket.](img/description_templates_v17_10.png)

> [!note]
> Vous pouvez créer des liens de raccourci pour créer un ticket à l'aide d'un modèle désigné. Par exemple : `https://gitlab.com/gitlab-org/gitlab/-/work_items/new?description_template=Feature%20proposal`. Pour en savoir plus, consultez la section [Création de tickets à l'aide d'une URL avec des valeurs préremplies](issues/create_issues.md#using-a-url-with-prefilled-values).

### Variables prises en charge dans les modèles de merge requests {#supported-variables-in-merge-request-templates}

> [!note]
> Cette fonctionnalité est disponible uniquement pour [le modèle par défaut](#set-a-default-template-for-merge-requests-and-issues).

Lorsque vous enregistrez une merge request pour la première fois, GitLab remplace ces variables dans votre modèle de merge request par leurs valeurs :

| Variable                                | Description                                                                                                                                                 | Exemple de résultat                                                                                                                                                                                   |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `%{all_commits}`                        | Messages de tous les commits de la merge request. Limité aux 100 commits les plus récents. Ignore les corps de commit dépassant 100 Kio et les messages de commit de fusion.        | `* Feature introduced` <br><br> `This commit implements feature` <br> `Changelog:added` <br><br> `* Bug fixed` <br><br> `* Documentation improved` <br><br>`This commit introduced better docs.` |
| `%{closes_issue}`                       | Référence au ticket déduite du nom de la branche source, s'il en existe une. Utilise `Related to` à la place de `Closes` lorsque la fermeture automatique des tickets est désactivée pour le projet. Lorsqu'un modèle utilise cette variable, la référence n'est pas ajoutée à la fin de la description. | `Closes #123`                                                                                                                                                                    |
| `%{co_authored_by}`                     | Noms et adresses e-mail des auteurs de commit au format trailer Git `Co-authored-by`. Limité aux auteurs des 100 commits les plus récents de la merge request.         | `Co-authored-by: Zane Doe <zdoe@example.com>` <br> `Co-authored-by: Blake Smith <bsmith@example.com>`                                                                                            |
| `%{first_commit}`                       | Message complet du premier commit dans le diff de la merge request.                                                                                                     | `Update README.md`                                                                                                                                                                               |
| `%{first_multiline_commit}`             | Message complet du premier commit qui n'est pas un commit de fusion et dont le corps de message comporte plus d'une ligne. Titre de la merge request si tous les commits ne sont pas multilignes. | `Update README.md` <br><br> `Improved project description in readme file.`                                                                                                                       |
| `%{first_multiline_commit_description}` | Description (sans la première ligne/le titre) du premier commit qui n'est pas un commit de fusion et dont le corps de message comporte plus d'une ligne.                        | `Improved project description in readme file.`                                                                                                                                                   |
| `%{source_branch}`                      | Le nom de la branche en cours de fusion.                                                                                                                        | `my-feature-branch`                                                                                                                                                                              |
| `%{target_branch}`                      | Le nom de la branche sur laquelle les modifications sont appliquées.                                                                                                     | `main`                                                                                                                                                                                           |

### Définir des modèles de description au niveau de l'instance {#set-instance-level-description-templates}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour les tickets et les merge requests, vous pouvez définir un modèle de description pour l'ensemble d'une instance en utilisant un [dépôt de modèles d'instance](../../administration/settings/instance_template_repository.md). Vous pouvez également utiliser le dépôt de modèles d'instance pour les modèles de fichiers.

Vous pourriez également être intéressé par les [modèles de projet](../../administration/project_templates.md) que vous pouvez utiliser lors de la création d'un nouveau projet dans l'instance.

### Définir des modèles de description au niveau du groupe {#set-group-level-description-templates}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Avec des modèles de description pour un groupe, vous pouvez sélectionner un projet dans le groupe pour stocker vos modèles. Vous pouvez ensuite accéder à ces modèles dans d'autres projets du groupe. Vous pouvez ainsi utiliser les mêmes modèles pour les tickets et les merge requests dans tous les projets du groupe.

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.
- Le projet doit être un enfant direct du groupe.

Pour réutiliser les modèles [que vous avez créés](#create-a-description-template) :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Modèles**.
1. Dans la liste déroulante, sélectionnez votre projet de modèles comme dépôt de modèles pour le groupe.
1. Sélectionnez **Enregistrer les modifications**.

![Paramètres des modèles de groupe.](img/group_file_template_settings_v11_5.png)

Vous pourriez également être intéressé par les modèles pour différents [types de fichiers dans les groupes](../group/manage.md#group-file-templates).

### Définir un modèle par défaut pour les merge requests et les tickets {#set-a-default-template-for-merge-requests-and-issues}

Dans un projet, vous pouvez choisir un modèle de description par défaut pour les nouveaux tickets et merge requests. Ainsi, chaque fois qu'une nouvelle merge request ou un nouveau ticket est créé, il est prérempli avec le texte que vous avez saisi dans le modèle.

Prérequis :

- Dans la barre latérale gauche de votre projet, sélectionnez **Paramètres** > **Général** et développez **Visibilité, fonctionnalités du projet, autorisations**. Assurez-vous que les tickets ou merge requests sont configurés sur **Tout le monde avec accès** ou sur **Uniquement les membres du projet**.

Pour définir un modèle de description par défaut pour les merge requests, effectuez l'une des opérations suivantes :

- [Créez un modèle de merge request](#create-a-merge-request-template) nommé `Default.md` (insensible à la casse) et enregistrez-le dans `.gitlab/merge_request_templates/`. Le modèle `Default.md` n'est pas prioritaire sur le modèle par défaut défini dans les paramètres du projet. Pour plus d'informations, voir [priorité des modèles de description par défaut](#priority-of-default-description-templates).
- Utilisateurs de GitLab Premium et Ultimate : définissez le modèle par défaut dans les paramètres du projet :

  1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
  1. Sélectionnez **Paramètres** > **Requêtes de fusion**.
  1. Dans la section **Modèle de description par défaut pour les requêtes de fusion**, remplissez la zone de texte.
  1. Sélectionnez **Enregistrer les modifications**.

Pour définir une description par défaut pour les éléments de travail, effectuez l'une des opérations suivantes :

- [Créez un modèle de description](#create-a-description-template) nommé `Default.md` (insensible à la casse) et enregistrez-le dans `.gitlab/issue_templates/`. Le modèle `Default.md` n'est pas prioritaire sur la description par défaut définie dans les paramètres du projet. Pour plus d'informations, voir [priorité des modèles de description par défaut](#priority-of-default-description-templates).
- Utilisateurs de GitLab Premium et Ultimate : définissez le modèle par défaut dans les paramètres du projet :

  1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
  1. Sélectionnez **Paramètres** > **Généralités**.
  1. Développez **Description par défaut des éléments de travail**.
  1. Remplissez la zone de texte.
  1. Sélectionnez **Enregistrer les modifications**.

Étant donné que les merge requests et les tickets GitLab prennent en charge le [Markdown](../markdown.md), vous pouvez l'utiliser pour mettre en forme du texte, notamment des titres et des listes.

Vous pouvez également fournir les attributs `issues_template` et `merge_requests_template` dans l'[API REST Projects](../../api/projects.md) pour maintenir vos modèles de tickets et de merge requests par défaut à jour.

#### Priorité des modèles de description par défaut {#priority-of-default-description-templates}

Lorsque vous définissez des [modèles de description de tickets](#set-a-default-template-for-merge-requests-and-issues) à différents endroits, ils disposent des priorités suivantes dans un projet. Les priorités supérieures remplacent celles qui se trouvent en dessous :

1. Modèle défini dans les paramètres du projet.
1. `Default.md` (insensible à la casse) du groupe parent.
1. `Default.md` (insensible à la casse) du dépôt du projet.

Les merge requests disposent de [règles d'héritage supplémentaires](merge_requests/creating_merge_requests.md) qui dépendent du contenu des messages de commit et des noms de branche.

## Exemple de modèle de description {#example-description-template}

Pour des exemples, consultez les modèles de description pour les tickets et les merge requests dans le [dossier `.gitlab`](https://gitlab.com/gitlab-org/gitlab/-/tree/master/.gitlab) du projet GitLab.

> [!note]
> Il est possible d'utiliser des [actions rapides](quick_actions.md) dans les modèles de description pour ajouter rapidement des labels, des personnes assignées et des jalons. Les actions rapides ne sont exécutées que si l'utilisateur qui soumet le ticket ou la merge request dispose des autorisations nécessaires pour effectuer les actions concernées.

Voici un exemple de modèle de rapport de bug :

```markdown
## Summary

<!-- HTML comments are not displayed -->
(Summarize the bug encountered concisely)

## Steps to reproduce

(How one can reproduce the issue - this is very important)

## Example Project

(If possible, create an example project here on GitLab.com that exhibits the problematic
behavior, and link to it here in the bug report.
If you are using an older version of GitLab, this will also determine whether the bug has been fixed
in a more recent version)

## What is the current bug behavior?

(What actually happens)

## What is the expected correct behavior?

(What you should see instead)

## Relevant logs and/or screenshots

(Paste any relevant logs - use code blocks (```) to format console output, logs, and code, as
it's very hard to read otherwise.)

## Possible fixes

(If you can, link to the line of code that might be responsible for the problem)

/label ~bug ~reproduced ~needs-investigation
/cc @project-manager
/assign @qa-tester
```
