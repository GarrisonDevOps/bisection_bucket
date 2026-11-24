---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Affichez les frameworks de conformité appliqués aux projets et aux groupes, avec des options pour gérer, filtrer et exporter les attributions de frameworks."
title: Rapport sur les projets de conformité
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Grâce au rapport sur les projets de conformité, vous pouvez voir les frameworks de conformité appliqués aux projets d'un groupe, d'un sous-groupe ou d'un projet. Chaque ligne du rapport affiche :

- Nom du projet.
- Chemin du projet.
- Les labels de framework de conformité si le projet en possède un ou plusieurs d'assignés.

Le framework par défaut du groupe possède un badge **par défaut**.

## Afficher le rapport sur les projets de conformité {#view-the-compliance-projects-report}

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour afficher le rapport sur les projets de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.

## Appliquer un framework de conformité aux projets d'un groupe {#apply-a-compliance-framework-to-projects-in-a-group}

{{< history >}}

- Possibilité d'ajouter des frameworks de conformité aux sous-groupes [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/469004) dans GitLab 17.2.
- Possibilité d'ajouter des frameworks de conformité aux projets [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/507986) dans GitLab 17.9.

{{< /history >}}

Vous pouvez appliquer un ou plusieurs frameworks de conformité aux projets d'un groupe, d'un sous-groupe ou d'un projet.

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

Pour appliquer un framework de conformité à un projet dans un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. À côté du projet auquel vous souhaitez ajouter le framework de conformité, sélectionnez l'action {{< icon name="pencil" >}}.
1. Sélectionnez un ou plusieurs frameworks de conformité existants ou créez-en un nouveau.

Pour appliquer un framework de conformité à plusieurs projets dans un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. Sélectionnez plusieurs projets.
1. Dans la liste déroulante **Choisir une action en bloc**, sélectionnez **Appliquer le framework aux projets sélectionnés**.
1. Sélectionnez le framework à appliquer.
1. Sélectionnez **Appliquer**.

## Supprimer un framework de conformité des projets d'un groupe {#remove-a-compliance-framework-from-projects-in-a-group}

{{< history >}}

- Possibilité de supprimer des frameworks de conformité des sous-groupes [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/469004) dans GitLab 17.2.
- Possibilité de supprimer des frameworks de conformité des projets [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/507986) dans GitLab 17.9.

{{< /history >}}

Vous pouvez supprimer un framework de conformité des projets d'un groupe, d'un sous-groupe ou d'un projet.

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

Pour supprimer un framework de conformité d'un projet dans un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. À côté du framework de conformité à supprimer du projet, sélectionnez {{< icon name="close" >}} sur le label du framework.

Pour supprimer un framework de conformité de plusieurs projets dans un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. Sélectionnez plusieurs projets.
1. Dans la liste déroulante **Choisir une action en bloc**, sélectionnez **Supprimer le framework des projets sélectionnés**.
1. Sélectionnez **Supprimer**.

## Exporter un rapport sur les frameworks de conformité des projets d'un groupe {#export-a-report-of-compliance-frameworks-on-projects-in-a-group}

Exportez un rapport sur les frameworks de conformité appliqués aux projets d'un groupe. Rapports :

- N'utilisent pas de filtres sur le rapport de framework.
- Sont tronqués à 15 Mo pour que la pièce jointe à l'e-mail ne soit pas trop volumineuse.

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour exporter un rapport sur les frameworks de conformité des projets d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Dans le coin supérieur droit, sélectionnez **Exporter**.
1. Sélectionnez **Exporter la liste des frameworks de projet**.

Un rapport est compilé et envoyé dans votre boîte de réception e-mail en pièce jointe.

## Filtrer le rapport sur les projets de conformité {#filter-the-compliance-projects-report}

Pour filtrer la liste des frameworks de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. Dans le champ de recherche :
   1. Sélectionnez l'attribut par lequel vous souhaitez filtrer.
   1. Sélectionnez un opérateur.
   1. Sélectionnez dans la liste des options ou saisissez du texte pour la recherche.
1. Sélectionnez **Rechercher**.

Répétez ce processus pour filtrer par plusieurs attributs.

## Créer un nouveau framework de conformité {#create-a-new-compliance-framework}

Vous pouvez créer de nouveaux frameworks de conformité sur les groupes principaux.

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour créer un nouveau framework de conformité depuis le rapport sur les projets de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. Sélectionnez **\+ Ajouter un cadriciel**.
1. Sélectionnez **Créer un nouveau framework**.
1. Sélectionnez **Ajouter un cadriciel** pour créer un framework de conformité.

## Modifier un framework de conformité {#edit-a-compliance-framework}

Vous pouvez modifier les frameworks de conformité sur les groupes principaux.

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour modifier un framework de conformité depuis le rapport sur les projets de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. Survolez le framework et sélectionnez **Modifier le framework**.
1. Sélectionnez **Enregistrer les modifications** pour modifier le framework de conformité.

## Supprimer un framework de conformité {#delete-a-compliance-framework}

Vous pouvez supprimer des frameworks de conformité des groupes principaux.

Prérequis :

- Vous devez être administrateur ou disposer du rôle Responsable sécurité ou Propriétaire pour le groupe.

Pour supprimer un framework de conformité depuis le rapport sur les projets de conformité :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Sur la page, sélectionnez l'onglet **Projets**.
1. Survolez le framework et sélectionnez **Modifier le framework**.
1. Sélectionnez **Supprimer le cadriciel** pour supprimer le framework de conformité.
