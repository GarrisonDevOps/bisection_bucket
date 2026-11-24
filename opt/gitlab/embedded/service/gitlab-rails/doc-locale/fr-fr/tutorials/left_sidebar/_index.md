---
stage: Growth
group: Engagement
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments-to-other-projects-and-subjects>.
title: 'Tutoriel : naviguer dans l''interface GitLab'
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- L'interface GitLab [a été modifiée](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/208474) pour adopter une disposition en panneaux dans GitLab 18.6.

{{< /history >}}

<!-- vale gitlab_base.FutureTense = NO -->

Suivez ce tutoriel pour apprendre à utiliser les différents éléments de l'interface afin de naviguer dans GitLab.

## Disposition de l'interface {#layout-of-the-interface}

Dans le coin supérieur droit, plusieurs raccourcis sont disponibles. Utilisez ces raccourcis pour créer de nouveaux éléments, et pour accéder à votre profil, à votre liste de tickets, de merge requests et d'éléments de la liste de tâches.

![Raccourcis dans la nouvelle navigation.](img/top_nav_v18_11.png)

La barre latérale gauche change en fonction des informations que vous consultez. Par exemple, vous pouvez être en train de consulter un projet, d'explorer des projets ou des groupes, ou de consulter votre profil. Pour accéder à d'autres sections de la barre latérale gauche, utilisez **Rechercher ou accéder à** dans la barre supérieure.

Le reste de la barre latérale gauche est renseigné en fonction de l'option que vous choisissez. Par exemple, si vous êtes dans un projet, la barre latérale est spécifique à ce projet.

À droite, la barre latérale GitLab Duo contient des boutons pour accéder à GitLab Duo Chat et aux sessions associées.

![Barre latérale GitLab Duo.](img/paneled_view_duo_sidebar_v18_11.png)

## Trouver votre projet {#find-your-project}

Passons maintenant en revue quelques tâches courantes pour lesquelles vous utiliserez la barre latérale gauche.

Pour commencer, nous allons trouver le projet sur lequel nous souhaitons travailler.

1. Pour explorer tous les projets disponibles, dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Choisissez dans la liste des projets fréquemment visités, ou saisissez un deux-points `:` suivi du nom du projet :

   ![Barre de recherche pour trouver vos projets et les projets fréquemment visités.](img/search_projects_v18_11.png)

La barre latérale gauche affiche désormais les options spécifiques au projet.

![Options spécifiques au projet](img/sidebar_v18_11.png)

## Épingler les éléments fréquemment utilisés {#pin-frequently-used-items}

Vous pouvez épingler des éléments de menu si vous les utilisez fréquemment.

1. Développez les sections jusqu'à afficher l'élément que vous souhaitez épingler.
1. Survolez et sélectionnez l'épingle ({{< icon name="thumbtack" >}}).

   ![Icône d'épingle sélectionnée.](img/pin_v18_11.png)

L'élément s'affiche dans la section **Épinglé** :

![Un élément dans la section Épinglé.](img/sidebar_v18_11_pinned.png)

> [!note]
> Les éléments que vous épinglez lorsque vous consultez un projet sont différents de ceux que vous épinglez lorsque vous consultez un groupe.

## Utiliser une vue plus ciblée {#use-a-more-focused-view}

Dans la barre latérale gauche, vous pouvez également choisir une vue plus ciblée des zones auxquelles vous avez accès. Sélectionnez **Rechercher ou accéder à**, puis sélectionnez **Votre travail**.

![La barre de recherche et l'élément Votre travail.](img/your_work_v18_11.png)

Ensuite, dans la barre latérale gauche, **Votre travail** s'affiche.

## Ouvrir les éléments de travail dans le panneau de détails {#open-work-items-in-the-details-panel}

Lorsque vous sélectionnez un élément de travail, comme un ticket, il s'ouvre dans un panneau de détails.

Pour ouvrir l'élément en vue pleine page, vous pouvez :

- Sur la page **Éléments de travail**, faites un clic droit sur l'élément et ouvrez-le dans un nouvel onglet.
- Sélectionnez l'élément, puis dans le panneau de détails, sélectionnez son identifiant (par exemple, `myproject#123456`).

Si l'espace à l'écran est suffisant, le panneau de détails s'ouvre à côté de la liste ou du tableau à partir duquel vous l'avez ouvert. Sur les écrans plus petits, le panneau de détails recouvre le panneau de liste ou de tableau.

![Ticket ouvert dans un panneau côte à côte avec le panneau Tickets.](img/paneled_view_issue_drawer_v18_11.png)

![Ticket ouvert dans un panneau recouvrant une partie du panneau Tickets.](img/paneled_view_issue_drawer_overlap_v18_11.png)

### Définir la préférence d'ouverture des éléments de travail dans un panneau {#set-preference-for-opening-work-items-in-a-panel}

Par défaut, les éléments de travail tels que les tickets ou les epics s'ouvrent dans le panneau de détails. Si vous préférez désactiver cette option :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet ou votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Forfait** > **Éléments de travail**.
1. À droite de la barre de filtres, sélectionnez **Options d'affichage** ({{< icon name="preferences" >}}) et désactivez le bouton bascule **Ouvrir les éléments dans le panneau latéral**.

Votre préférence est enregistrée et s'applique à l'ensemble de GitLab.

## Accéder à la zone Admin {#go-to-the-admin-area}

La zone **Admin** est accessible dans le coin supérieur droit :

![Le bouton de la zone Admin dans la nouvelle navigation.](img/admin_area_v18_11.png)

## Accéder aux Nouveautés {#access-whats-new}

La fonctionnalité **Nouveautés** présente aux utilisateurs certains points forts des nouvelles fonctionnalités des 10 dernières versions de GitLab.

Si vous êtes connecté :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Nouveautés pour vous**.

Si vous n'êtes pas connecté :

1. Dans la barre latérale gauche, en bas, sélectionnez **Aide** ({{< icon name="question" >}}).
1. Sélectionnez **Nouveautés pour vous**.

L'élément de menu **Nouveautés pour vous** indique le nombre d'éléments que vous n'avez pas encore lus.
