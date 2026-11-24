---
stage: Software Supply Chain Security
group: Authorization
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Autorisations affinées pour Git et autres opérations
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/596613) dans GitLab 19.2.

{{< /history >}}

Un jeton d'accès personnel à granularité fine ne peut accéder qu'aux ressources et aux autorisations que vous lui accordez. Pour l'utiliser avec Git et d'autres opérations, créez un jeton et définissez sa portée. Pour plus d'informations, consultez [les jetons d'accès personnels à granularité fine](fine_grained_access_tokens.md).

Dans les tableaux suivants :

- **Ressource** et **Permission** correspondent à la ressource et à l'autorisation à sélectionner lors de la création du jeton.
- **Accès** est le périmètre qui doit contenir la ressource cible. Un jeton dont la portée est définie sur un groupe autorise également les opérations sur les projets de ce groupe.

## Opérations Git {#git-operations}

Un jeton d'accès personnel à granularité fine utilisé comme mot de passe pour Git via HTTPS doit disposer des autorisations suivantes :

| Opération                          | Ressource | Permission | Accès        |
| ---------------------------------- | -------- | ---------- | ------------- |
| Cloner ou extraire un dépôt de projet | Code     | Télécharger   | Projet       |
| Envoyer vers un dépôt de projet       | Code     | Push       | Projet       |
| Cloner ou extraire un wiki               | Wiki     | Lire       | Projet, Groupe[^project-wikis-use] |
| Envoyer vers un wiki                     | Wiki     | Créer     | Projet, Groupe[^project-wikis-use] |
| Cloner ou extraire un snippet            | Snippet  | Lire       | Projet, Utilisateur[^project-snippets-use] |
| Envoyer vers un snippet                  | Snippet  | Mettre à jour     | Projet, Utilisateur[^project-snippets-use] |
| Télécharger des objets Git LFS           | Code     | Télécharger   | Projet       |
| Envoyer des objets Git LFS             | Code     | Push       | Projet       |

[^project-wikis-use]: les wikis de projet utilisent le périmètre du projet et les wikis de groupe utilisent le périmètre du groupe.
[^project-snippets-use]: les snippets de projet utilisent le périmètre du projet et les snippets personnels utilisent le périmètre de l'utilisateur.

## Registre de conteneurs {#container-registry}

Un jeton d'accès personnel à granularité fine utilisé pour se connecter au [registre de conteneurs](../../user/packages/container_registry/authenticate_with_container_registry.md) doit disposer des autorisations suivantes :

| Opération                                     | Ressource             | Permission | Accès  |
| --------------------------------------------- | -------------------- | ---------- | ------- |
| Extraire des images de conteneurs                         | Dépôt de conteneurs | Lire       | Projet |
| Supprimer des images de conteneurs et des tags              | Dépôt de conteneurs | Supprimer     | Projet |

> [!note]
> Vous ne pouvez pas utiliser des jetons d'accès personnels à granularité fine pour envoyer des images de conteneurs.

## Proxy de dépendances {#dependency-proxy}

Un jeton d'accès personnel à granularité fine utilisé pour se connecter au [proxy de dépendances](../../user/packages/dependency_proxy/_index.md) doit disposer des autorisations suivantes :

| Opération                                     | Ressource         | Permission | Accès |
| --------------------------------------------- | ---------------- | ---------- | ------ |
| Extraire des images de conteneurs via le proxy de dépendances | Proxy de dépendances | Lire  | Groupe  |

## Téléchargements d'archives et de ressources associées à une release {#archive-and-release-asset-downloads}

| Opération                                     | Ressource | Permission | Accès  |
| --------------------------------------------- | -------- | ---------- | ------- |
| Télécharger une archive de dépôt                 | Code     | Télécharger   | Projet |
| Télécharger une ressource associée à une release depuis un lien direct   | Release  | Lire       | Projet |

## Flux RSS et calendriers {#rss-and-calendar-feeds}

Un jeton d'accès personnel à granularité fine utilisé pour authentifier les requêtes de flux RSS ou iCalendar doit disposer des autorisations suivantes :

| Flux                                          | Ressource              | Permission | Accès               |
| --------------------------------------------- | --------------------- | ---------- | -------------------- |
| Activité de l'utilisateur                                 | Activité              | Lire       | Utilisateur                 |
| Activité du projet                              | Événement                 | Lire       | Projet              |
| Activité du groupe                                | Événement                 | Lire       | Groupe                |
| Commits du projet                               | Code                  | Lire       | Projet              |
| Tags du projet                                  | Code                  | Lire       | Projet              |
| Tickets et éléments de travail, y compris les calendriers    | Élément de travail             | Lire       | Projet, Groupe, Utilisateur |
| Merge requests                                | Merge Request         | Lire       | Projet, Groupe       |
| Vos projets                                 | Projet               | Lire       | Utilisateur                 |
| Calendrier d'expiration des jetons d'accès personnels     | Jeton d'accès personnel | Lire       | Utilisateur                 |

## Autres opérations {#other-operations}

| Opération                                     | Ressource         | Permission | Accès         |
| --------------------------------------------- | ---------------- | ---------- | -------------- |
| Télécharger une image de gestion de conception            | Élément de travail        | Lire       | Projet        |
| Récupérer un module Go depuis un projet privé      | Code             | Télécharger   | Projet        |
| Transmettre les événements de télémétrie de l'extension d'éditeur     | Télémétrie de l'éditeur | Créer     | Utilisateur           |
| Recevoir des mises à jour de commentaires en direct via WebSocket   | Élément de travail        | Lire       | Projet, Groupe |
