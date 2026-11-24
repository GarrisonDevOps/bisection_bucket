---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Tickets croisés
description: "Liez des tickets entre eux depuis des messages de commit, des tickets liés, des merge requests et des noms de branches pour assurer le suivi des travaux connexes."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les liens croisés créent des relations entre les tickets dans GitLab. Les liens croisés :

- Connectent les tickets associés pour un meilleur suivi et une meilleure visibilité.
- Lient les tickets à leurs commits et merge requests associés.
- Créent des références via des messages de commit, des noms de branches et des descriptions.
- Fonctionnent entre projets et groupes.
- Affichent les relations dans la section **Éléments liés** de chaque ticket.

Vous pouvez créer des liens croisés via :

- [Messages de commit](#from-commit-messages)
- [Tickets liés](#from-linked-issues)
- [Les merge requests](#from-merge-requests)
- [Noms de branches](#from-branch-names)
- [Liens d'éléments de travail explicites](../../work_items/_index.md#work-items-in-merge-requests)

## Depuis les messages de commit {#from-commit-messages}

Chaque fois que vous mentionnez un ticket dans votre message de commit, vous créez une relation entre les deux étapes du workflow de développement : le ticket lui-même et le premier commit associé à ce ticket.

Si le ticket et le code que vous committez se trouvent tous les deux dans le même projet, ajoutez `#xxx` au message de commit, où `xxx` est le numéro du ticket.

```shell
git commit -m "this is my commit message. Ref #xxx"
```

Les messages de commit ne peuvent généralement pas commencer par un caractère `#`, vous pouvez donc également utiliser la notation alternative `GL-xxx` :

```shell
git commit -m "GL-xxx: this is my commit message"
```

S'ils se trouvent dans des projets différents, mais dans le même groupe, ajoutez `projectname#xxx` au message de commit.

```shell
git commit -m "this is my commit message. Ref projectname#xxx"
```

S'ils ne se trouvent pas dans le même groupe, vous pouvez ajouter l'URL complète du ticket (`https://gitlab.com/<username>/<projectname>/-/issues/<xxx>`).

> [!note]
> Pour des raisons de performances, GitLab ne traite que les 1 000 premières URL complètes dans les messages de commit pour la création automatique de liens. Les URL supplémentaires au-delà de cette limite ne sont pas converties en liens.

```shell
git commit -m "this is my commit message. Related to https://gitlab.com/<username>/<projectname>/-/issues/<xxx>"
```

Bien entendu, vous pouvez remplacer `gitlab.com` par l'URL de votre propre instance GitLab.

Lier votre premier commit à votre ticket est utile pour suivre votre processus avec [GitLab Value Stream Analytics](https://about.gitlab.com/solutions/value-stream-management/). Il mesure le temps consacré à la planification de la mise en œuvre de ce ticket, c'est-à-dire le temps écoulé entre la création d'un ticket et le premier commit.

## Depuis les tickets liés {#from-linked-issues}

Mentionner des tickets liés dans des merge requests et d'autres tickets aide les membres de votre équipe et vos collaborateurs à savoir que des tickets ouverts existent sur le même sujet.

Lorsque vous mentionnez le ticket `#111` dans le ticket `#222`, le ticket `#111` affiche également une notification dans son fil **Activité**. Autrement dit, il vous suffit de mentionner la relation une seule fois pour qu'elle s'affiche dans les deux tickets. Il en va de même lorsque vous mentionnez des tickets dans des [merge requests](#from-merge-requests).

Lorsque le fil d'activité d'un ticket est filtré sur **Afficher uniquement l'historique** ou **Afficher toute l'activité**, les liens croisés s'affichent sous la forme `(Username) mentioned in issue #(number) (time ago)`.

## Depuis les merge requests {#from-merge-requests}

Mentionner des tickets dans les commentaires de merge requests fonctionne exactement de la même façon que pour les [tickets liés](#from-linked-issues).

Lorsque vous mentionnez un ticket dans la description d'une merge request, cela [lie le ticket et la merge request entre eux](#from-linked-issues). En outre, vous pouvez également [définir la fermeture automatique d'un ticket](managing_issues.md#closing-issues-automatically) dès que la merge request est fusionnée.

Lorsque le fil d'activité d'un ticket est filtré sur **Afficher uniquement l'historique** ou **Afficher toute l'activité**, les liens croisés s'affichent sous la forme `(Username) mentioned in merge request !(number) (time ago)`.

## Depuis les noms de branches {#from-branch-names}

Lorsque vous créez une branche dans le même projet qu'un ticket et que vous commencez le nom de la branche par le numéro du ticket, suivi d'un trait d'union, le ticket et la merge request que vous créez sont liés. Pour plus d'informations, consultez [préfixer les noms de branches avec des numéros de tickets](../repository/branches/_index.md#prefix-branch-names-with-a-number).
