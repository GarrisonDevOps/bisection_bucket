---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Associer une réunion Zoom à un ticket
description: "Associez une réunion Zoom à un ticket à l'aide de l'action rapide /zoom pour que les membres de l'équipe puissent rejoindre un appel rapidement."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour communiquer de manière synchrone dans le cadre de la gestion des incidents, vous pouvez associer une réunion Zoom à un ticket. Après avoir démarré un appel Zoom pour une intervention d'urgence, vous avez besoin d'un moyen d'associer la conférence téléphonique à un ticket. Cela permet aux membres de votre équipe de rejoindre la réunion rapidement sans avoir à demander un lien.

## Ajouter une réunion Zoom à un ticket {#adding-a-zoom-meeting-to-an-issue}

Pour associer une réunion Zoom à un ticket, vous pouvez utiliser [l'action rapide `/zoom`](../quick_actions.md#zoom).

Dans un ticket, laissez un commentaire en utilisant l'action rapide `/zoom` suivie d'un lien Zoom valide :

```shell
/zoom https://zoom.us/j/123456789
```

Si l'URL de la réunion Zoom est valide et que vous disposez du rôle Reporter, Developer, Maintainer ou Owner, une alerte système vous informe de son ajout réussi. La description du ticket est automatiquement modifiée pour inclure le lien Zoom, et un bouton apparaît juste sous le titre du ticket.

![Vue d'un ticket GitLab affichant un bouton Rejoindre la réunion Zoom.](img/zoom_quickaction_button_v16_6.png)

Vous ne pouvez associer qu'une seule réunion Zoom à un ticket. Si vous tentez d'ajouter une deuxième réunion Zoom à l'aide de l'action rapide `/zoom`, cela ne fonctionne pas. Vous devez d'abord [la supprimer](#removing-an-existing-zoom-meeting-from-an-issue).

Les utilisateurs disposant de GitLab Premium et GitLab Ultimate peuvent également [ajouter plusieurs liens Zoom aux incidents](../../../operations/incident_management/linked_resources.md#link-zoom-meetings-from-an-incident).

## Supprimer une réunion Zoom existante d'un ticket {#removing-an-existing-zoom-meeting-from-an-issue}

De la même manière que pour l'ajout d'une réunion Zoom, vous pouvez la supprimer à l'aide d'une action rapide :

```shell
/remove_zoom
```

Vous pouvez également utiliser [l'action rapide `/remove_zoom`](../quick_actions.md#remove_zoom).

Si vous disposez du rôle Reporter, Developer, Maintainer ou Owner, une alerte système vous informe que l'URL de la réunion a bien été supprimée.
