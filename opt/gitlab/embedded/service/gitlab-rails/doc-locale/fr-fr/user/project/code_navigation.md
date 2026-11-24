---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Navigation dans le code
description: "Trouvez où les symboles sont définis et appelés, à l'aide du graphe de connaissances de GitLab Orbit."
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com
- Statut : version bêta

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/234404) en tant que [version bêta](../../policy/development_stages_support.md#beta) dans GitLab 19.0 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `orbit_code_intelligence`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/work_items/599054) dans GitLab 19.4.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

La navigation dans le code vous aide à comprendre un code inconnu et la façon dont il se connecte au reste du projet.

La navigation dans le code lit le graphe de connaissances que [GitLab Orbit](https://docs.gitlab.com/orbit/indexed-data/) construit à partir de votre code et met à jour au fur et à mesure que vous poussez des modifications. À partir de ce graphe, il lit les fichiers de votre projet, les classes, modules, méthodes et fonctions qu'ils définissent, ainsi que les symboles qui s'appellent mutuellement. Elle ne nécessite ni indexeur ni job CI/CD.

Pour un symbole sélectionné, la navigation dans le code affiche les éléments suivants :

- Références : les endroits du projet qui appellent ce symbole, également affichés sous forme de nombre d'appels.
- Appels : les symboles que ce symbole appelle.
- Définition : un lien vers le fichier et la ligne où le symbole est défini.

## Afficher la navigation dans le code pour un fichier {#view-code-navigation-for-a-file}

Prérequis :

- Le rôle Reporter, Developer, Maintainer ou Owner pour le projet.
- [GitLab Orbit activé](https://docs.gitlab.com/orbit/remote/getting-started/) pour le groupe principal du projet.
- Un fichier sur la branche par défaut du projet. GitLab Orbit n'indexe pas les autres branches.

Pour afficher la navigation dans le code pour un fichier :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Dépôt**.
1. Sélectionnez un fichier sur la branche par défaut.
1. Dans le coin supérieur droit du fichier, sélectionnez **Navigation dans le code** ({{< icon name="code" >}}).

Si vous avez récemment activé GitLab Orbit pour votre groupe principal, [l'indexation](https://docs.gitlab.com/orbit/remote/indexing/) est peut-être encore en cours. Le panneau répertorie les symboles une fois l'indexation terminée.

Pour voir où un symbole est utilisé :

1. Dans le panneau, sélectionnez un symbole.
1. Sélectionnez **Références** pour voir les symboles qui l'appellent, ou **Appels** pour voir les symboles qu'il appelle.
1. Sélectionnez un résultat pour ouvrir le fichier à la ligne correspondante.

Pour revenir à la liste complète des symboles, sélectionnez **Retour aux symboles**.

## Langages pris en charge {#supported-languages}

La navigation dans le code couvre les langages indexés par GitLab Orbit. Pour la liste à jour, consultez la documentation [GitLab Orbit](https://docs.gitlab.com/orbit/).
