---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Utilisez les branches Git pour développer de nouvelles fonctionnalités. Ajoutez des protections de branches aux branches critiques pour vous assurer que seuls les utilisateurs de confiance peuvent y effectuer des merge requests.
title: Branche par défaut
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous créez un nouveau [projet](../../_index.md), GitLab crée une branche par défaut dans le dépôt. Une branche par défaut dispose d'options de configuration spéciales qui ne sont pas partagées par les autres branches :

- Elle ne peut pas être supprimée.
- Elle est [initialement protégée](protected.md) contre les poussées forcées.
- Lorsqu'une merge request utilise un [modèle de fermeture de ticket](../../issues/managing_issues.md#closing-issues-automatically) pour fermer un ticket, le travail est fusionné dans cette branche.

Le nom de la branche par défaut de votre [nouveau projet](../../_index.md) dépend des modifications de configuration apportées à votre instance ou à votre groupe par votre administrateur GitLab. GitLab vérifie d'abord les personnalisations spécifiques, puis vérifie à un niveau plus large, en utilisant la valeur par défaut de GitLab uniquement si aucune personnalisation n'est définie :

1. Un nom de branche par défaut personnalisé [spécifique au projet](#change-the-default-branch-name-for-a-project).
1. [Nom de branche par défaut de groupe personnalisé](#change-the-default-branch-name-for-new-projects-in-a-group) spécifié dans le sous-groupe direct d'un projet.
1. Nom de branche par défaut de groupe personnalisé spécifié dans le groupe principal d'un projet.
1. Un nom de branche par défaut personnalisé défini pour l'[instance](#change-the-default-branch-name-for-new-projects-in-an-instance).
1. Si aucun nom de branche par défaut personnalisé n'est défini à quelque niveau que ce soit, GitLab utilise par défaut `main`.

Dans l'interface utilisateur de GitLab, vous pouvez modifier les valeurs par défaut à n'importe quel niveau. GitLab fournit également les [commandes Git nécessaires](#update-the-default-branch-name-in-your-repository) pour mettre à jour votre copie du dépôt.

## Modifier le nom de la branche par défaut pour un projet {#change-the-default-branch-name-for-a-project}

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.

Pour mettre à jour la branche par défaut d'un [projet](../../_index.md) individuel :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Paramètres par défaut des branches**. Pour **Branche par défaut**, sélectionnez une nouvelle branche par défaut.
1. Facultatif. Cochez la case **Fermer automatiquement les tickets référencés sur la branche par défaut** pour fermer les tickets lorsqu'une merge request [utilise un modèle de fermeture](../../issues/managing_issues.md#closing-issues-automatically).
1. Sélectionnez **Enregistrer les modifications**.

Vous pouvez également utiliser l'attribut `default_branch` de l'[API projets](../../../../api/projects.md). Lorsque vous créez un projet avec l'API et que vous définissez `initialize_with_readme` sur `true`, vous pouvez spécifier le paramètre `default_branch` comme suit :

- Un nom de branche. Par exemple, `main`.
- Une référence complète. Par exemple, `refs/heads/main`.

L'API supprime le préfixe `refs/heads/` si vous fournissez une référence complète.

## Modifier le nom de la branche par défaut pour les nouveaux projets dans une instance {#change-the-default-branch-name-for-new-projects-in-an-instance}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les [administrateurs](../../../permissions.md) de GitLab Self-Managed peuvent personnaliser la branche initiale pour les projets hébergés sur cette instance. Les groupes et sous-groupes individuels peuvent remplacer la valeur par défaut de l'instance pour leurs projets.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Branche par défaut**.
1. Pour **Nom initial de la branche par défaut**, sélectionnez une nouvelle branche par défaut.
1. Sélectionnez **Enregistrer les modifications**.

Les projets créés sur cette instance après la modification du paramètre utilisent le nom de branche personnalisé, sauf si une configuration de groupe ou de sous-groupe le remplace.

## Modifier le nom de la branche par défaut pour les nouveaux projets dans un groupe {#change-the-default-branch-name-for-new-projects-in-a-group}

Prérequis :

- Vous devez disposer du rôle Propriétaire pour le groupe et les sous-groupes.

Pour modifier le nom de la branche par défaut pour les nouveaux projets dans un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Branche par défaut**.
1. Pour **Nom initial de la branche par défaut**, sélectionnez une nouvelle branche par défaut.
1. Sélectionnez **Enregistrer les modifications**.

Les projets créés dans ce groupe après la modification du paramètre utilisent le nom de branche personnalisé, sauf si une configuration de sous-groupe le remplace.

## Protéger les branches par défaut initiales {#protect-initial-default-branches}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les administrateurs GitLab et les propriétaires de groupes peuvent définir des [protections de branches](protected.md) à appliquer à la branche par défaut de chaque dépôt pour l'instance, ou pour des groupes individuels, avec l'une des options suivantes :

- **Entièrement protégée** \- Valeur par défaut. Les développeurs ne peuvent pas pousser de nouveaux commits, mais les mainteneurs le peuvent. Personne ne peut effectuer de poussée forcée.
- **Entièrement protégée après la poussée initiale** \- Les développeurs peuvent pousser le commit initial vers un dépôt, mais aucun autre ensuite. Les mainteneurs peuvent toujours pousser. Personne ne peut effectuer de poussée forcée.
- **Protégée contre les poussées** \- Les développeurs ne peuvent pas pousser de nouveaux commits, mais sont autorisés à accepter des merge requests vers la branche. Les mainteneurs peuvent pousser vers la branche.
- **Partiellement protégée** \- Les développeurs et les mainteneurs peuvent pousser de nouveaux commits, mais ne peuvent pas effectuer de poussée forcée.
- **Non protégée** \- Les développeurs et les mainteneurs peuvent pousser de nouveaux commits et effectuer des poussées forcées.

> [!warning]
> Sauf si l'option **Entièrement protégée** est choisie, un développeur malveillant pourrait tenter de voler vos données sensibles. Par exemple, un fichier `.gitlab-ci.yml` malveillant pourrait être commité sur une branche protégée et, si un pipeline est ensuite exécuté contre cette branche, entraîner l'exfiltration de variables CI/CD de groupe.

### Pour tous les projets d'une instance {#for-all-projects-in-an-instance}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Ce paramètre s'applique uniquement à la branche par défaut de chaque dépôt. Pour protéger d'autres branches, vous devez soit :

- Configurer la [protection des branches dans le dépôt](protected.md).
- Configurer la [protection des branches pour les groupes](../../../group/manage.md#change-the-default-branch-protection-of-a-group).

Les administrateurs des instances GitLab Self-Managed peuvent personnaliser la protection initiale de la branche par défaut pour les projets hébergés sur cette instance. Les groupes et sous-groupes individuels peuvent remplacer le paramètre par défaut de l'instance pour leurs projets.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Branche par défaut**.
1. Sélectionnez [**Protection initiale de la branche par défaut**](#protect-initial-default-branches).
1. Pour autoriser les propriétaires de groupes à remplacer la protection de la branche par défaut de l'instance, sélectionnez [**Allow owners to manage default branch protection per group**](#prevent-overrides-of-default-branch-protection).
1. Sélectionnez **Enregistrer les modifications**.

#### Empêcher les remplacements de la protection de la branche par défaut {#prevent-overrides-of-default-branch-protection}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les propriétaires de groupes peuvent remplacer les protections des branches par défaut définies pour l'ensemble d'une instance, groupe par groupe. Avec [GitLab Premium ou Ultimate](https://about.gitlab.com/pricing/), les administrateurs GitLab peuvent désactiver ce privilège pour les propriétaires de groupes, en appliquant la règle de protection définie pour l'instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez la section **Branche par défaut**.
1. Décochez la case **Allow owners to manage default branch protection per group**.
1. Sélectionnez **Enregistrer les modifications**.

> [!note]
> Les administrateurs GitLab peuvent toujours mettre à jour la protection de la branche par défaut d'un groupe.

### Pour tous les projets d'un groupe {#for-all-projects-in-a-group}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les propriétaires de groupes peuvent remplacer les protections des branches par défaut définies pour l'ensemble d'une instance, groupe par groupe. Avec [GitLab Premium ou Ultimate](https://about.gitlab.com/pricing/), les administrateurs GitLab peuvent [appliquer la protection des branches par défaut initiales](#prevent-overrides-of-default-branch-protection), ce qui verrouille ce paramètre pour les propriétaires de groupes.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Branche par défaut**.
1. Sélectionnez [**Protection initiale de la branche par défaut**](#protect-initial-default-branches).
1. Sélectionnez **Enregistrer les modifications**.

## Mettre à jour le nom de la branche par défaut dans votre dépôt {#update-the-default-branch-name-in-your-repository}

> [!warning]
> La modification du nom de votre branche par défaut peut potentiellement interrompre les tests, la configuration CI/CD, les services, les utilitaires auxiliaires et toutes les intégrations utilisées par votre dépôt. Avant de modifier ce nom de branche, consultez les propriétaires et les mainteneurs de votre projet. Assurez-vous qu'ils comprennent que la portée de ce changement inclut les références à l'ancien nom de branche dans le code et les scripts associés.

Lorsque vous modifiez le nom de la branche par défaut d'un dépôt existant, ne créez pas de nouvelle branche. Préservez l'historique de votre branche par défaut en la renommant. Cet exemple renomme la branche par défaut d'un dépôt Git (`example`) :

1. Sur votre ligne de commande locale, accédez à votre dépôt `example` et assurez-vous que vous êtes sur la branche par défaut :

   ```plaintext
   cd example
   git checkout master
   ```

1. Renommez la branche par défaut existante avec le nouveau nom (`main`). L'argument `-m` transfère tout l'historique des commits vers la nouvelle branche :

   ```plaintext
   git branch -m master main
   ```

1. Poussez la branche `main` nouvellement créée en amont, et configurez votre branche locale pour suivre la branche distante du même nom :

   ```plaintext
   git push -u origin main
   ```

1. Si vous prévoyez de supprimer l'ancienne branche par défaut, mettez à jour `HEAD` pour qu'il pointe vers votre nouvelle branche par défaut, `main` :

   ```plaintext
   git symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main
   ```

1. Connectez-vous à GitLab avec au moins le rôle Mainteneur et suivez les instructions pour [modifier la branche par défaut de ce projet](#change-the-default-branch-name-for-a-project). Sélectionnez `main` comme nouvelle branche par défaut.
1. Protégez votre nouvelle branche `main` comme décrit dans la [documentation sur les branches protégées](protected.md).
1. Facultatif. Si vous souhaitez supprimer l'ancienne branche par défaut :
   1. Vérifiez que rien ne pointe vers elle.
   1. Supprimez la branche sur le dépôt distant :

      ```plaintext
      git push origin --delete master
      ```

      Vous pouvez supprimer la branche ultérieurement, après avoir confirmé que la nouvelle branche par défaut fonctionne comme prévu.

1. Informez les contributeurs de votre projet de ce changement, car ils doivent également effectuer certaines actions :

   - Les contributeurs doivent récupérer la nouvelle branche par défaut dans leur copie locale du dépôt.
   - Les contributeurs ayant des merge requests ouvertes ciblant l'ancienne branche par défaut doivent manuellement rediriger ces merge requests pour utiliser `main` à la place.
1. Dans votre dépôt, mettez à jour toutes les références à l'ancien nom de branche dans votre code.
1. Mettez à jour les références à l'ancien nom de branche dans le code et les scripts associés qui résident en dehors de votre dépôt, comme les utilitaires auxiliaires et les intégrations.

## Redirection après renommage de la branche par défaut {#default-branch-rename-redirect}

Les URL pointant vers des fichiers ou des répertoires spécifiques dans un projet intègrent le nom de la branche par défaut du projet et se trouvent souvent dans la documentation ou les favoris du navigateur. Lorsque vous [mettez à jour le nom de la branche par défaut dans votre dépôt](#update-the-default-branch-name-in-your-repository), ces URL changent et doivent être mises à jour.

Pour faciliter la période de transition, chaque fois que la branche par défaut d'un projet est modifiée, GitLab enregistre le nom de l'ancienne branche par défaut. Si cette branche est supprimée, les tentatives d'affichage d'un fichier ou d'un répertoire sur celle-ci sont redirigées vers la branche par défaut actuelle, au lieu d'afficher la page « introuvable ».

## Sujets connexes {#related-topics}

- [Configurer une branche par défaut pour votre wiki](../../wiki/_index.md)
- [Discussion sur le renommage de la branche par défaut](https://lore.kernel.org/git/pull.656.v4.git.1593009996.gitgitgadget@gmail.com/) sur la liste de diffusion Git
- [Article de blog de mars 2021 : le nouveau nom de branche par défaut de Git](https://about.gitlab.com/blog/new-git-default-branch-name/)

## Dépannage {#troubleshooting}

### Impossible de modifier la branche par défaut : réinitialisation vers la branche actuelle {#unable-to-change-default-branch-resets-to-current-branch}

Nous suivons ce problème dans le [ticket 20474](https://gitlab.com/gitlab-org/gitlab/-/issues/20474). Ce problème survient souvent lorsqu'une branche nommée `HEAD` est présente dans le dépôt. Pour résoudre le problème :

1. Dans votre dépôt local, créez une nouvelle branche temporaire et poussez-la :

   ```shell
   git checkout -b tmp_default && git push -u origin tmp_default
   ```

1. Dans GitLab, procédez à la [modification de la branche par défaut](#change-the-default-branch-name-for-a-project) vers cette branche temporaire.
1. Depuis votre dépôt local, supprimez la branche `HEAD` :

   ```shell
   git push -d origin HEAD
   ```

1. Dans GitLab, [modifiez la branche par défaut](#change-the-default-branch-name-for-a-project) vers celle que vous souhaitez utiliser.

### Interroger GraphQL pour les branches par défaut {#query-graphql-for-default-branches}

Vous pouvez utiliser une [requête GraphQL](../../../../api/graphql/_index.md) pour récupérer les branches par défaut de tous les projets d'un groupe.

Pour retourner tous les projets sur une seule page de résultats, remplacez `GROUPNAME` par le chemin complet de votre groupe. GitLab renvoie la première page de résultats. Si `hasNextPage` est `true`, vous pouvez demander la page suivante en remplaçant la valeur `null` dans `after: null` par la valeur de `endCursor` :

```graphql
{
 group(fullPath: "GROUPNAME") {
   projects(after: null) {
     pageInfo {
       hasNextPage
       endCursor
     }
     nodes {
       name
       repository {
         rootRef
       }
     }
   }
 }
}
```

### Les nouveaux sous-groupes n'héritent pas du nom de la branche par défaut d'un sous-groupe de niveau supérieur {#new-subgroups-do-not-inherit-default-branch-name-from-a-higher-level-subgroup}

Lorsque vous configurez une branche par défaut dans un sous-groupe qui contient un autre sous-groupe contenant lui-même un projet, la branche par défaut n'est pas héritée.

Nous suivons ce problème dans le [ticket 327208](https://gitlab.com/gitlab-org/gitlab/-/issues/327208).
