---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Topics de projet
description: "Organisation du projet, abonnement et affichage."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : version bêta

{{< /details >}}

Les sujets sont des labels que vous pouvez attribuer aux projets pour vous aider à les organiser et à les retrouver. Un sujet est généralement un nom court qui décrit le contenu ou l'objectif d'un projet. Vous pouvez attribuer un sujet à plusieurs projets.

Par exemple, vous pouvez créer et attribuer les sujets `python` et `hackathon` à tous les projets qui utilisent Python et sont destinés à des contributions à des hackathons.

Les sujets attribués à un projet sont affichés dans les listes **Vue d'ensemble du projet** et [**Projets**](working_with_projects.md#view-projects), sous la description du projet.

> [!note]
> Seuls les utilisateurs ayant accès au projet peuvent voir les sujets qui lui sont attribués, mais tout le monde (y compris les utilisateurs non authentifiés) peut voir les sujets disponibles sur l'instance GitLab. N'incluez pas d'informations sensibles dans le nom d'un sujet.

## Explorer les sujets {#explore-topics}

Pour explorer les sujets de projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**.
1. Sélectionnez **Explorer**.
1. Dans la barre latérale gauche, sélectionnez **Sujets**. La page **Explorer les sujets** affiche la liste de tous les sujets de projet.
1. Facultatif. Pour filtrer les sujets par nom, saisissez vos critères de recherche dans la zone de recherche.
1. Pour afficher les projets associés à un sujet, sélectionnez un sujet. Vous pouvez également accéder à la page d'un sujet via l'URL `https://gitlab.com/explore/projects/topics/<topic-name>`.

## Filtrer et trier les sujets {#filter-and-sort-topics}

Sur la page de sujet du projet, vous pouvez filtrer la liste des projets ayant ce sujet par :

- Nom
- Langage
- Visibilité
- Propriétaire
- Projets archivés

Vous pouvez également trier les projets par :

- Date
- Nom
- Nombre d'étoiles
- Pour filtrer les projets par nom, saisissez vos critères de recherche dans la zone de recherche.
- Pour trier les projets selon d'autres critères, sélectionnez une option dans les listes déroulantes.

## S'abonner à un sujet {#subscribe-to-a-topic}

Si vous souhaitez savoir quand de nouveaux projets sont ajoutés à un sujet, vous pouvez utiliser son flux RSS.

Vous pouvez effectuer cette opération depuis la page **Explorer les sujets** ou depuis un projet avec des sujets.

Pour s'abonner à un sujet :

- Depuis la page **Explorer les sujets** :
  1. Dans la barre latérale gauche, développez le chevron le plus en haut ({{< icon name="chevron-down" >}}).
  1. Sélectionnez **Explorer**.
  1. Sélectionnez **Sujets**.
  1. Sélectionnez le sujet auquel vous souhaitez vous abonner.
  1. Dans le coin supérieur droit, sélectionnez **S'abonner au flux des nouveaux projets** ({{< icon name="rss" >}}).
- Depuis un projet :
  1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
  1. Dans la page **Vue d'ensemble du projet**, dans la liste **Sujets**, sélectionnez le sujet auquel vous souhaitez vous abonner.
  1. Dans le coin supérieur droit, sélectionnez **S'abonner au flux des nouveaux projets** ({{< icon name="rss" >}}).

Les résultats sont affichés sous forme de flux RSS au format Atom. L'URL du résultat contient un jeton de flux et la liste des projets ayant ce sujet. Vous pouvez ajouter cette URL à votre lecteur de flux.

## Attribuer des sujets à un projet {#assign-topics-to-a-project}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour attribuer des sujets à un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Nommage, description, sujets**.
1. Dans la zone de texte **Sujets du projet**, recherchez un sujet. Des sujets populaires sont suggérés au fur et à mesure de votre saisie.
1. Sélectionnez **Enregistrer les modifications**.

## Administrer les sujets {#administer-topics}

Les administrateurs d'instance peuvent administrer tous les sujets de projet depuis la [page Sujets de la zone **Admin**](../../administration/admin_area.md#administering-topics).
