---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Créez et utilisez des champs personnalisés pour les éléments de travail afin de suivre des informations spécifiques à votre workflow. Configurez les types de champs pour améliorer les capacités de planification et de reporting."
title: Champs personnalisés
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/479571) dans GitLab 17.11 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `custom_fields_feature`. Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/479571) dans GitLab 18.0. Suppression du feature flag `custom_fields_feature`.

{{< /history >}}

Les champs personnalisés ajoutent des informations spécialisées aux éléments de travail, tels que les tickets et les epics, correspondant à vos besoins de planification spécifiques. Configurez des champs personnalisés pour un groupe afin de suivre des données telles que la valeur métier, l'évaluation des risques, le classement des priorités ou les attributs d'équipe. Ces champs apparaissent dans tous les éléments de travail du groupe, de ses sous-groupes et de ses projets.

Les champs personnalisés aident les équipes à standardiser la façon dont elles enregistrent et communiquent les informations dans l'ensemble du workflow. Cette standardisation crée une cohérence entre les projets et permet des capacités de filtrage et de reporting plus puissantes. Choisissez parmi différents types de champs pour répondre à différentes exigences en matière de données et de scénarios de planification :

- Sélection unique
- Sélection multiple
- Nombre
- Texte

## Configurer des champs personnalisés pour un groupe {#configure-custom-fields-for-a-group}

Configurez des champs personnalisés pour les groupes principaux afin de les rendre disponibles pour les éléments de travail de ce groupe, de ses sous-groupes et de ses projets.

### Créer un champ personnalisé {#create-a-custom-field}

Créez des champs personnalisés pour capturer les informations spécifiques que votre équipe doit suivre. Vous pouvez configurer chaque champ pour un ou plusieurs types d'éléments de travail, en adaptant votre workflow aux exigences de votre organisation.

Gardez ces limites à l'esprit :

- Un groupe principal peut avoir au maximum 50 champs personnalisés actifs.
- Un type d'élément de travail peut avoir au maximum 10 champs personnalisés qui lui sont assignés.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire pour le groupe.

Pour créer un champ personnalisé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe. Ce groupe doit être au niveau principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Éléments de travail**.
1. Sélectionnez **Créer un champ**.
1. Remplissez les champs :
   - Dans **Type**, sélectionnez le type du champ :
     - Sélection unique
     - Sélection multiple
     - Nombre
     - Champ de texte

     Le type de champ ne peut pas être modifié après la création du champ.
   - Dans **Utiliser pour**, sélectionnez les types d'éléments de travail pour lesquels vous souhaitez que ce champ soit disponible.
   - Dans **Options** (pour les champs à sélection unique et à sélection multiple), saisissez les options de sélection possibles. Un champ à sélection unique ou à sélection multiple peut avoir au maximum 50 options de sélection.
     - Réorganisez les options en faisant glisser l'icône de poignée ({{< icon name="grip" >}}) à gauche de chaque option.
     - Pour ajouter plusieurs options à la fois, sélectionnez le champ de saisie et collez une liste d'éléments, un par ligne.
1. Sélectionnez **Enregistrer**.

### Modifier un champ personnalisé {#edit-a-custom-field}

Modifiez les champs personnalisés existants pour refléter l'évolution des besoins de votre organisation. Vous pouvez modifier le nom d'un champ, les types d'éléments de travail auxquels il s'applique et les options disponibles sans perdre les données existantes.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire pour le groupe.

Pour modifier un champ personnalisé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe. Ce groupe doit être au niveau principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Éléments de travail**.
1. En regard du champ que vous souhaitez modifier, sélectionnez **Modifier `<field name>`** ({{< icon name="pencil" >}}).
1. Apportez les modifications souhaitées aux champs.
1. Sélectionnez **Mettre à jour**.

### Archiver un champ personnalisé {#archive-a-custom-field}

Archivez les champs personnalisés dont vous n'avez plus besoin tout en préservant leurs données historiques. L'archivage supprime le champ de tous les éléments de travail qui le contenaient.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire pour le groupe.

Pour archiver un champ personnalisé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe. Ce groupe doit être au niveau principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Éléments de travail**.
1. En regard du champ que vous souhaitez archiver, sélectionnez **Archiver `<field name>`** ({{< icon name="archive" >}}).

### Désarchiver un champ personnalisé {#unarchive-a-custom-field}

Restaurez un champ personnalisé précédemment archivé lorsque vous avez besoin de l'utiliser à nouveau. Les éléments de travail pour lesquels des valeurs ont été définies pour ce champ conservent les mêmes valeurs qu'avant l'archivage du champ.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire pour le groupe.

Pour désarchiver un champ personnalisé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe. Ce groupe doit être au niveau principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Éléments de travail**.
1. Sélectionnez **Archivées** pour afficher la liste des champs archivés.
1. En regard du champ que vous souhaitez désarchiver, sélectionnez **Désarchiver `<field name>`** ({{< icon name="redo" >}}).

## Définir les valeurs des champs personnalisés pour un élément de travail {#set-custom-field-values-for-a-work-item}

Ajoutez des informations pertinentes aux éléments de travail en utilisant les champs personnalisés configurés pour votre groupe.

Prérequis :

- Vous devez disposer du rôle Planificateur, Reporter, Développeur, Mainteneur ou Propriétaire pour le projet ou le groupe de l'élément de travail.
- Si vous disposez du rôle Invité, vous ne pouvez définir des champs personnalisés que lors de la création d'un élément de travail.

1. Accédez à un élément de travail.
1. Dans la barre latérale droite, trouvez la section correspondant au champ personnalisé que vous souhaitez modifier, puis sélectionnez **Modifier**.
1. Saisissez ou sélectionnez la valeur souhaitée.
   - La valeur d'un champ de texte peut contenir au maximum 1 024 caractères.
1. Sélectionnez une zone quelconque en dehors du champ.

## Guide de sélection du type de champ {#field-type-selection-guide}

Lors de la création de champs personnalisés, choisissez un type de champ qui correspond au type de données que vous souhaitez suivre. Le bon type de champ améliore la qualité des données et rend le reporting plus efficace.

### Champs à sélection unique {#single-select-fields}

Utilisez des champs à sélection unique lorsque :

- Les utilisateurs doivent choisir exactement une option dans une liste prédéfinie.
- Les options sont mutuellement exclusives.
- Vous souhaitez assurer la cohérence et empêcher les saisies libres.

Les champs à sélection unique conviennent bien pour :

- Les indicateurs de priorité (comme `High`, `Medium`, `Low`)
- Les affectations de catégories
- Les affectations d'équipes
- Les états d'approbation
- Les niveaux de priorité

### Champs à sélection multiple {#multi-select-fields}

Utilisez des champs à sélection multiple lorsque :

- Plusieurs valeurs peuvent s'appliquer simultanément.
- Vous devez suivre des attributs qui se recoupent.
- Des éléments peuvent appartenir à plusieurs catégories.

Les champs à sélection multiple conviennent bien pour :

- Les tags ou labels
- Les compétences requises
- Les composants affectés
- Les groupes de parties prenantes
- Les capacités des fonctionnalités

### Champs numériques {#number-fields}

Utilisez des champs numériques lorsque :

- Vous devez collecter des données quantitatives.
- Vous souhaitez effectuer des calculs ou des agrégations.
- Les informations doivent pouvoir être triées numériquement.

Les champs numériques conviennent bien pour :

- Les estimations de coûts
- Les estimations de temps
- Les scores de valeur métier
- Les scores de classement ou de priorisation
- Le pourcentage d'avancement

### Champs de texte {#text-fields}

Utilisez des champs de texte lorsque :

- Vous devez capturer des informations uniques qui ne correspondent pas à des catégories prédéfinies.
- Les données sont très variables.
- Vous devez fournir du contexte ou des détails.

Les champs de texte conviennent bien pour :

- Le contexte supplémentaire
- Les identifiants de référence externes
- Les informations de contact
- Les notes ou commentaires brefs
- Les URL ou liens

## Conventions de nommage des champs personnalisés {#naming-conventions-for-custom-fields}

Des conventions de nommage cohérentes pour les champs personnalisés les rendent plus faciles à comprendre et à utiliser. De bons noms de champs améliorent l'adoption et la qualité des données.

### Directives générales {#general-guidelines}

- Gardez des noms concis mais descriptifs.
- Utilisez un langage clair et précis que votre organisation comprend.
- Soyez cohérent dans l'utilisation des majuscules (la casse de titre est recommandée).
- Évitez les abréviations, sauf si elles sont largement comprises.
- Incluez l'unité de mesure lorsque cela est applicable.

### Nommer les champs à sélection unique et à sélection multiple {#naming-single-select-and-multi-select-fields}

Commencez par le nom de la catégorie, suivi d'un descripteur. Par exemple :

- `Risk Level` plutôt que `Risk`
- `Customer Segment` plutôt que `Segment`
- `Development Phase` plutôt que `Phase`
- `Approval Status` plutôt que `Status`

### Nommer les champs numériques {#naming-number-fields}

Incluez l'unité de mesure dans le nom du champ. Par exemple :

- `Effort Points` plutôt que `Points`
- `Budget Estimate ($)` plutôt que `Budget`
- `Implementation Time (days)` plutôt que `Time`
- `Business Value Score` plutôt que `Value`

### Nommer les champs de texte {#naming-text-fields}

Indiquez clairement les informations à saisir. Par exemple :

- `External Reference ID` plutôt que `Reference`
- `Implementation Notes` plutôt que `Notes`
- `Requirements Source` plutôt que `Source`

### Préfixes spécifiques aux équipes {#team-specific-prefixes}

Si plusieurs équipes utilisent la même instance GitLab, envisagez d'ajouter des préfixes d'équipe pour éviter toute confusion :

- `DEV: Sprint Priority`
- `QA: Test Environment`
- `UX: Design Status`
- `PM: Market Segment`

Cette approche aide les équipes à identifier rapidement les champs pertinents pour leur travail.
