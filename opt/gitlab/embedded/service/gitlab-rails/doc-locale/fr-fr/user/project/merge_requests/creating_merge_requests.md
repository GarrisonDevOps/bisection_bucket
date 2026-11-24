---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Comment créer des merge requests dans GitLab.
title: Créer des merge requests
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous êtes prêt à créer une merge request, utilisez une méthode adaptée à votre workflow. Vous pouvez créer une merge request :

- Dans l'interface GitLab.
- Depuis la ligne de commande, avec la commande [`glab mr`](https://gitlab.com/gitlab-org/cli/-/tree/main/docs/source/mr), ou des commandes Git combinées avec les [options de push](../../../topics/git/commit.md#push-options).
- Dans l'[extension Visual Studio Code](../../../editor_extensions/visual_studio_code/_index.md).
- En envoyant un e-mail.
- Avec [l'API des merge requests](../../../api/merge_requests.md).

Lorsque vous créez une merge request, GitLab applique les règles de nommage des branches de votre projet. Pour associer votre merge request à une branche, suivez les [patterns de nommage des branches](../repository/branches/_index.md#name-your-branch).

Les titres de merge request bénéficient d'une [prise en charge limitée de la mise en forme](../../markdown.md#work-item-and-merge-request-titles).

## Depuis la barre supérieure {#from-the-top-bar}

Vous pouvez créer une merge request depuis la barre supérieure dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre projet.
1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) puis **Nouvelle requête de fusion**.

## Depuis la liste des merge requests {#from-the-merge-request-list}

Vous pouvez créer une merge request depuis la liste des merge requests.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Dans le coin supérieur droit, sélectionnez **Nouvelle requête de fusion**.
1. Sélectionnez une branche source et une branche cible, puis sélectionnez **Comparer les branches et continuer**.
1. Remplissez les champs de la page **Nouvelle requête de fusion**, puis sélectionnez **Créer une requête de fusion**.

Chaque branche ne peut être associée qu'à une seule merge request ouverte. Si une merge request existe déjà pour cette branche, un lien vers la merge request existante est affiché.

## Depuis la page des commits {#from-the-commits-page}

Vous pouvez créer une merge request depuis l'historique des commits de votre branche.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Commits**.
1. En haut, ouvrez la liste déroulante **Sélectionner une révision Git**, puis sélectionnez une branche autre que la branche par défaut.
1. Dans le coin supérieur droit, sélectionnez **Créer une requête de fusion**.
1. Remplissez les champs de la page **Nouvelle requête de fusion**, puis sélectionnez **Créer une requête de fusion**.

Si une merge request ouverte existe déjà pour la branche, le bouton affiche **Voir la requête de fusion ouverte** à la place, et ouvre la merge request existante.

## Depuis un ticket {#from-an-issue}

Si votre workflow de développement requiert un ticket pour chaque merge request, vous pouvez créer une branche directement depuis le ticket pour accélérer le processus. La nouvelle branche, et ultérieurement sa merge request, sont marquées comme liées à ce ticket. Après la fusion de la merge request, le ticket est fermé automatiquement, sauf si la [fermeture automatique des tickets est désactivée](../issues/managing_issues.md#disable-automatic-issue-closing).

### Nouvelle branche depuis un ticket {#new-branch-from-an-issue}

Pour créer une branche et une merge request en même temps :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**, puis filtrez par **Type** = **Ticket** et sélectionnez votre ticket.
1. Allez au bas de la description du ticket.
1. Sélectionnez **Créer une requête de fusion** > **Créer une requête de fusion et une branche**.
1. Dans la boîte de dialogue, vérifiez le nom de branche suggéré. Il est basé sur le [modèle de nom de branche](../repository/branches/_index.md) de votre projet.
1. Facultatif. Si le nom de branche est déjà utilisé ou si vous avez besoin d'un nom différent, renommez-la.
1. Sélectionnez une branche source ou un tag.
1. Sélectionnez **Créer une requête de fusion**.

### Branche existante depuis un ticket {#existing-branch-from-an-issue}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/525989) dans GitLab 17.11.

{{< /history >}}

Prérequis :

- Une branche doit déjà être liée au ticket.
- Vous devez disposer de l'autorisation de créer des merge requests dans le projet.

Pour créer une merge request lorsqu'une branche est déjà liée dans Développement :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**, puis filtrez par **Type** = **Ticket** et sélectionnez votre ticket.
1. Dans la section **Développement**, trouvez la branche liée.
1. Sélectionnez le menu des actions de la branche ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez **Créer une requête de fusion**.
1. Remplissez les champs de la page **Nouvelle requête de fusion**, puis sélectionnez **Créer une requête de fusion**.

Le formulaire de merge request est pré-rempli avec les mots-clés appropriés pour le lier au ticket.

## Depuis une tâche {#from-a-task}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/477785) dans GitLab 17.8.

{{< /history >}}

Si votre équipe décompose les tickets en tâches, vous pouvez créer une branche directement depuis la tâche pour accélérer le processus. La nouvelle branche, et ultérieurement sa merge request, sont marquées comme liées à cette tâche. Après la fusion de la merge request, la tâche est fermée automatiquement, sauf si la [fermeture automatique des tickets est désactivée](../issues/managing_issues.md#disable-automatic-issue-closing).

### Nouvelle branche depuis une tâche {#new-branch-from-a-task}

Prérequis :

- Vous devez disposer du rôle Développeur, Mainteneur ou Propriétaire pour le projet contenant la tâche.

Pour créer une branche et une merge request en même temps :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**, puis filtrez par **Type** = **Tâche** et sélectionnez votre tâche.
1. Allez au bas de la description de la tâche.
1. Sélectionnez **Créer une requête de fusion**.
1. Dans la boîte de dialogue, vérifiez le nom de branche suggéré. Il est basé sur le [modèle de nom de branche](../repository/branches/_index.md) de votre projet.
1. Facultatif. Si le nom de branche est déjà utilisé ou si vous avez besoin d'un nom différent, renommez-la.
1. Sélectionnez une branche source ou un tag.
1. Sélectionnez **Créer une requête de fusion**.

### Branche existante depuis une tâche {#existing-branch-from-a-task}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/work_items/525989) dans GitLab 17.11.

{{< /history >}}

Prérequis :

- Une branche doit déjà être liée à la tâche.
- Vous devez disposer de l'autorisation de créer des merge requests dans le projet.

Pour créer une merge request lorsqu'une branche est déjà liée dans Développement :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**, puis filtrez par **Type** = **Tâche** et sélectionnez votre tâche.
1. Dans la section **Développement**, trouvez la branche liée.
1. Sélectionnez le menu des actions de la branche ({{< icon name="ellipsis_v" >}}).
1. Sélectionnez **Créer une requête de fusion**.
1. Remplissez les champs de la page **Nouvelle requête de fusion**, puis sélectionnez **Créer une requête de fusion**.

Le formulaire de merge request est pré-rempli avec les mots-clés appropriés pour le lier à la tâche.

## Lorsque votre dépôt Git est vide {#when-your-git-repository-is-empty}

Si votre dépôt Git est vide lorsque vous créez une merge request depuis un ticket ou une tâche, GitLab :

- Crée une branche par défaut.
- Effectue un commit d'un fichier `README.md` vide dans cette branche.
- Crée une nouvelle branche basée sur le titre du ticket ou de la tâche et vous y redirige.
- Si votre projet est configuré avec un service de déploiement tel que Kubernetes, vous invite à configurer le [déploiement automatique](../../../topics/autodevops/stages.md#auto-deploy) en vous aidant à créer un fichier `.gitlab-ci.yml`.

## Fermeture automatique des tickets et des tâches {#automatic-issue-and-task-closing}

Si le nom de la branche que vous créez est [préfixé par le numéro du ticket ou de la tâche](../repository/branches/_index.md#prefix-branch-names-with-a-number), GitLab crée un lien croisé entre le ticket ou la tâche et la merge request, et ajoute le [pattern de fermeture](../issues/managing_issues.md#closing-issues-automatically) à la description de la merge request. Dans la plupart des cas, cela ressemble à `Closes #ID`, où `ID` est l'identifiant du ticket ou de la tâche. Si votre projet est configuré avec un pattern de fermeture, le ticket ou la tâche est fermé lorsque la merge request est fusionnée.

> [!note]
> Les éléments de travail liés avec des patterns de fermeture (comme `Closes #123`) ou mentionnés avec des mots-clés (comme `Related to #456`) apparaissent automatiquement dans le widget **Éléments de travail** dans la barre latérale de la merge request. Pour plus d'informations, consultez [les éléments de travail dans les merge requests](../../work_items/_index.md#work-items-in-merge-requests).

## Depuis l'éditeur Web {#from-the-web-editor}

Vous pouvez créer des merge requests avec l'[éditeur Web](../repository/web_editor.md) lorsque vous :

- Créez, modifiez, chargez ou supprimez un fichier.
- Créez un répertoire.

## Lorsque vous créez une branche {#when-you-create-a-branch}

Vous pouvez créer une merge request lorsque vous créez une branche.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Branches**.
1. Saisissez un nom de branche et sélectionnez **Nouvelle branche**.
1. Au-dessus de la liste des fichiers, sélectionnez **Créer une requête de fusion**. Une merge request est créée. La branche par défaut est la cible.
1. Remplissez les champs et sélectionnez **Créer une requête de fusion**.

## Lorsque vous travaillez dans une duplication {#when-you-work-in-a-fork}

Vous pouvez créer une merge request depuis votre duplication pour contribuer au projet principal.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre duplication.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**, et sélectionnez **Nouvelle requête de fusion**.
1. Pour **Branche source**, sélectionnez la branche dans votre duplication qui contient vos modifications.
1. Pour **Branche cible** :

   1. Sélectionnez le dépôt amont, et non votre duplication. Si vous contribuez fréquemment des modifications en amont, envisagez de définir une cible par défaut pour votre duplication.
   1. Sélectionnez une branche depuis le dépôt amont :

      ![La liste déroulante pour sélectionner la branche cible dans le dépôt amont.](img/forking_workflow_branch_select_v15_9.png)

   > [!note]
   > Si la visibilité de votre duplication est plus restrictive que celle du dépôt parent, la branche cible est définie par défaut sur la branche par défaut de votre duplication. Cela évite l'exposition potentielle d'informations privées dans votre duplication.

1. Sélectionnez **Comparer les branches et continuer**.
1. Sélectionnez **Créer une requête de fusion**. La merge request est créée dans le dépôt cible, et non dans votre duplication.
1. Si vous disposez du rôle Développeur, Mainteneur ou Propriétaire, ajoutez les personnes assignées, les relecteurs, les labels et les jalons souhaités.
1. Sélectionnez **Soumettre la merge request**.

Si la merge request cible un autre dépôt, elle utilise :

- Les règles d'approbation du projet cible.
- La configuration CI/CD, les ressources et les variables CI/CD du projet de votre duplication.

Pour exécuter des pipelines CI/CD dans le projet amont, [vous devez être membre de ce projet](../../../ci/pipelines/merge_request_pipelines.md#use-with-forked-projects). Si vous exécutez un pipeline de merge request dans le projet parent pour une merge request provenant d'une duplication, toutes les variables deviennent disponibles pour le pipeline.

Une fois votre travail fusionné, [dissociez votre duplication](../repository/forking_workflow.md#unlink-a-fork) de son dépôt amont si vous ne prévoyez pas d'effectuer d'autres contributions.

### Définir le projet cible par défaut {#set-the-default-target-project}

Par défaut, les merge requests provenant d'une duplication ciblent le dépôt amont, et non votre duplication. Vous pouvez configurer votre dépôt dupliqué comme cible par défaut, plutôt que le dépôt amont.

Prérequis :

- Vous travaillez dans une duplication.
- Vous devez disposer du rôle Développeur, Mainteneur ou Propriétaire, ou être autorisé à créer des merge requests dans le projet.
- Le dépôt amont autorise la création de merge requests.
- Les [paramètres de visibilité](../../public_access.md#change-project-visibility) de la duplication doivent correspondre ou être moins restrictifs que ceux du dépôt amont. Par exemple : ce paramètre n'est pas affiché si votre duplication est privée, mais que le dépôt amont est public.

Pour cela :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Requêtes de fusion**.
1. Dans la section **Projet cible**, sélectionnez l'option que vous souhaitez utiliser pour votre projet cible par défaut.
1. Sélectionnez **Enregistrer les modifications**.

## Par envoi d'un e-mail {#by-sending-an-email}

{{< history >}}

- **Envoyer une nouvelle requête de fusion par email pour ce projet** [renommé](https://gitlab.com/gitlab-org/gitlab/-/issues/560277) en **Envoyer une requête de fusion par e-mail pour ce projet** dans GitLab 18.6.

{{< /history >}}

Vous pouvez créer une merge request en envoyant un e-mail à GitLab. La branche cible de la merge request est la branche par défaut du dépôt.

Prérequis :

- La merge request doit cibler le dépôt actuel, et non un dépôt amont.
- Un administrateur GitLab doit configurer les [e-mails entrants](../../../administration/incoming_email.md). Ce paramètre est activé sur GitLab.com.
- Un administrateur GitLab doit configurer la [réponse par e-mail](../../../administration/reply_by_email.md). Ce paramètre est activé sur GitLab.com.
- Vous devez disposer du rôle Développeur, Mainteneur ou Propriétaire, ou être autorisé à créer des merge requests dans le projet.

Pour créer une merge request en envoyant un e-mail :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Si le projet contient des merge requests, sélectionnez **Envoyer une requête de fusion par e-mail pour ce projet**.
1. Dans la boîte de dialogue, copiez l'adresse e-mail affichée. Gardez cette adresse privée. Toute personne qui la possède peut créer des tickets ou des merge requests comme si elle était vous.
1. Ouvrez un e-mail et rédigez un message avec les informations suivantes :

   - La ligne **Au** est l'adresse e-mail que vous avez copiée.
   - Le **Objet** est le nom de la branche source.
   - Le corps de l'e-mail est la description de la merge request.

1. Pour ajouter des commits, joignez des fichiers `.patch` au message.
1. Envoyez l'e-mail.

Une merge request est créée.

> [!warning]
> L'adresse e-mail est unique pour chaque utilisateur et doit être gardée privée. Toute personne ayant accès à l'adresse e-mail peut l'utiliser pour créer des merge requests et des tickets comme si elle était vous. Si vous pensez que cette adresse e-mail privée a été partagée ou divulguée, [réinitialisez le jeton](../../../security/tokens/_index.md#reset-an-incoming-email-token) immédiatement.

### Ajouter des pièces jointes lors de la création d'une merge request par e-mail {#add-attachments-when-creating-a-merge-request-by-email}

Ajoutez des commits à une merge request en ajoutant des patches en pièces jointes à l'e-mail.

- La taille combinée des patches doit être de 2 Mo ou moins.
- Pour être considérée comme un patch, le nom de fichier de la pièce jointe doit se terminer par `.patch`.
- Les patches sont traités dans l'ordre alphabétique par nom.
- Si la branche source du sujet n'existe pas, elle est créée depuis le `HEAD` du dépôt, ou la branche cible par défaut. Pour modifier manuellement la branche cible, utilisez l'action rapide `/target_branch`.
- Si la branche source existe déjà, les patches sont appliqués par-dessus celle-ci.

## Sujets connexes {#related-topics}

- [API de merge requests](../../../api/merge_requests.md)
- [Actions rapides](../quick_actions.md)

## Dépannage {#troubleshooting}

### Aucune option pour créer une merge request sur un ticket {#no-option-to-create-a-merge-request-on-an-issue}

L'option **Créer une requête de fusion** ne s'affiche pas sur un ticket si :

- Une branche portant le même nom existe déjà.
- Une merge request existe déjà pour cette branche.
- Votre projet a une relation de duplication active.
- Votre projet est privé et le ticket est confidentiel.

Pour faire apparaître ce bouton, une solution de contournement possible est de [supprimer la relation de duplication de votre projet](../repository/forking_workflow.md#unlink-a-fork). Après la suppression, vous ne pouvez pas restaurer la relation de duplication. Votre projet ne peut plus envoyer ni recevoir de merge requests vers le projet source, ni vers ses autres duplications.

### Le message e-mail n'a pas pu être traité {#email-message-could-not-be-processed}

Lors de l'envoi d'un e-mail pour créer une merge request, si vous tentez de cibler un dépôt amont, GitLab répond avec cette erreur :

```plaintext
Unfortunately, your email message to GitLab could not be processed.

You are not allowed to perform this action. If you believe this is in error, contact a staff member.
```
