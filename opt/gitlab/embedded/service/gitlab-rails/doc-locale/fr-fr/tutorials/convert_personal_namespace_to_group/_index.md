---
stage: Tenant Scale
group: Organizations
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments-to-other-projects-and-subjects>.
title: 'Tutoriel : convertir un espace de nommage personnel en groupe'
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com

{{< /details >}}

Si vous avez débuté avec un [espace de nommage](../../user/namespace/_index.md) personnel, mais que vous avez dépassé ses capacités, vous pouvez passer à un espace de nommage de groupe à la place. Avec un espace de nommage de groupe, vous pouvez créer plusieurs sous-groupes et gérer leurs membres et leurs autorisations.

Vous n'avez pas à repartir de zéro. Vous pouvez créer un nouveau groupe et déplacer vos projets existants vers ce groupe pour bénéficier d'avantages supplémentaires. Pour en savoir plus, consultez [Tutoriel : déplacer votre projet personnel vers un groupe](../move_personal_project_to_group/_index.md).

Vous pouvez également aller plus loin et convertir votre espace de nommage personnel en espace de nommage de groupe. La conversion de votre espace de nommage vous permet de conserver le nom d'utilisateur et l'URL existants. Par exemple, si votre nom d'utilisateur est `alex`, vous pouvez continuer à utiliser l'URL `https://gitlab.example.com/alex` pour votre groupe.

Ce tutoriel vous montre comment convertir votre espace de nommage personnel en espace de nommage de groupe en suivant les étapes ci-dessous :

1. [Créer un groupe](#create-a-group).
1. [Transférer les projets de l'espace de nommage personnel vers le groupe](#transfer-projects-from-the-personal-namespace-to-the-group).
1. [Renommer le nom d'utilisateur d'origine](#rename-the-original-username).
1. [Renommer le nouvel espace de nommage de groupe avec le nom d'utilisateur d'origine](#rename-the-new-group-namespace-to-the-original-username).

Par exemple, si votre nom d'utilisateur pour un espace de nommage personnel est `alex`, créez d'abord un espace de nommage de groupe nommé `alex-group`. Ensuite, déplacez tous les projets de l'espace de nommage `alex` vers l'espace de nommage `alex-group`. Enfin, renommez l'espace de nommage `alex` en `alex-user`, et l'espace de nommage `alex-group` avec le nom d'utilisateur désormais disponible `alex`.

## Créer un groupe {#create-a-group}

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau groupe**.
1. Dans **Nom du groupe**, saisissez un nom pour le groupe.
1. Dans **URL du groupe**, saisissez un chemin pour le groupe, qui sera utilisé comme espace de nommage. Ne vous inquiétez pas du chemin réel, il n'est que temporaire. Vous modifierez cette URL pour qu'elle corresponde au nom d'utilisateur de l'espace de nommage personnel lors de la [dernière étape](#rename-the-new-group-namespace-to-the-original-username).
1. Choisissez le [niveau de visibilité](../../user/public_access.md).
1. Facultatif. Renseignez les informations pour personnaliser votre expérience.
1. Sélectionnez **Créer un groupe**.

## Transférer les projets de l'espace de nommage personnel vers le groupe {#transfer-projects-from-the-personal-namespace-to-the-group}

Ensuite, vous devez transférer vos projets de l'espace de nommage personnel vers le nouveau groupe. Vous ne pouvez transférer qu'un seul projet à la fois. Si vous souhaitez transférer plusieurs projets, vous devez effectuer les étapes ci-dessous pour chaque projet.

Avant de commencer le processus de transfert, assurez-vous de :

- Disposer du rôle Propriétaire pour le projet.
- Supprimer les [images de conteneur](../../user/packages/container_registry/_index.md#move-or-rename-container-registry-repositories). Vous ne pouvez pas transférer un projet qui contient des images de conteneur.
- Supprimer les packages npm. Vous ne pouvez pas mettre à jour l'espace de nommage racine d'un projet qui contient des packages npm.

Pour transférer un projet vers un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Paramètres avancés**.
1. Sous **Transférer le projet**, choisissez le groupe vers lequel transférer le projet.
1. Sélectionnez **Transférer le projet**.
1. Saisissez le nom du projet et sélectionnez **Confirmer**.

## Renommer le nom d'utilisateur d'origine {#rename-the-original-username}

Ensuite, renommez le nom d'utilisateur d'origine de l'espace de nommage personnel, afin que le nom d'utilisateur devienne disponible pour le nouvel espace de nommage de groupe. Vous pouvez continuer à utiliser l'espace de nommage personnel pour d'autres projets personnels, ou [supprimer ce compte utilisateur](../../user/profile/account/delete_account.md)

À partir du moment où vous renommez l'espace de nommage personnel, le nom d'utilisateur devient disponible et il est possible qu'une autre personne enregistre un compte avec ce nom. Pour éviter cela, vous devez [renommer le nouveau groupe](#rename-the-new-group-namespace-to-the-original-username) dès que possible.

Pour [modifier le nom d'utilisateur](../../user/profile/_index.md#change-your-username) :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Modifier le profil**.
1. Dans la barre latérale gauche, sélectionnez **Compte**.
1. Dans la section **Changer le nom d'utilisateur**, saisissez un nouveau nom d'utilisateur comme chemin.
1. Sélectionnez **Mettre à jour le nom d'utilisateur**.

## Renommer le nouvel espace de nommage de groupe avec le nom d'utilisateur d'origine {#rename-the-new-group-namespace-to-the-original-username}

Enfin, renommez l'URL du nouveau groupe avec le nom d'utilisateur de l'espace de nommage personnel d'origine.

Pour [modifier le chemin de votre groupe](../../user/group/manage.md#change-a-groups-path) (URL du groupe) :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Paramètres avancés**.
1. Sous **Modifier l'URL du groupe**, saisissez le nom d'utilisateur d'origine de l'utilisateur.
1. Sélectionnez **Modifier l'URL du groupe**.

Et voilà ! Vous avez maintenant converti un espace de nommage personnel en groupe, ce qui ouvre de nouvelles possibilités pour travailler sur des projets et collaborer avec davantage de membres.
