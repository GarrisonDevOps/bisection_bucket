---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Engineering Workflow Management (EWM)
description: "Configurez l'intégration Engineering Workflow Management (EWM) pour lier les éléments de travail EWM mentionnés dans les merge requests et les messages de commit."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Grâce à l'intégration EWM, vous pouvez accéder depuis GitLab aux éléments de travail EWM mentionnés dans les descriptions de merge requests et les messages de commit. Chaque référence à un élément de travail est automatiquement convertie en lien vers cet élément de travail.

Ce produit IBM [s'appelait auparavant Rational Team Concert (RTC)](https://jazz.net/blog/index.php/2019/04/23/renaming-the-ibm-continuous-engineering-portfolio/). Cette intégration est compatible avec toutes les versions de RTC et EWM.

Pour activer l'intégration EWM dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **EWM**.
1. Sous **Activer l'intégration**, cochez la case **Actif**.
1. Remplissez les champs obligatoires :

   - **URL du projet** : L'URL vers la zone de projet EWM.

     Pour obtenir l'URL de votre zone de projet, accédez au chemin `/ccm/web/projects` et copiez l'URL du projet répertorié. Par exemple, `https://example.com/ccm/web/Example%20Project`.
   - **URL du ticket** : L'URL vers l'éditeur d'éléments de travail dans la zone de projet EWM.

     Le format est `<your-server-url>/resource/itemName/com.ibm.team.workitem.WorkItem/:id`. GitLab remplace `:id` par le numéro du ticket (par exemple, `https://example.com/ccm/resource/itemName/com.ibm.team.workitem.WorkItem/:id`, qui devient `https://example.com/ccm/resource/itemName/com.ibm.team.workitem.WorkItem/123`).
   - **URL de nouveau ticket** : URL permettant de créer un nouvel élément de travail dans la zone de projet EWM.

     Ajoutez le fragment suivant à l'URL de votre zone de projet : `#action=com.ibm.team.workitem.newWorkItem`. Par exemple, `https://example.com/ccm/web/projects/JKE%20Banking#action=com.ibm.team.workitem.newWorkItem`.

1. Facultatif. Sélectionnez **Tester les paramètres**.
1. Sélectionnez **Enregistrer les modifications**.

## Référencer les éléments de travail EWM dans les messages de commit {#reference-ewm-work-items-in-commit-messages}

Pour faire référence à des éléments de travail, vous pouvez utiliser n'importe quel mot-clé pris en charge par le kit d'outils d'intégration Git EWM. Utilisez le format : `<keyword> <id>`.

Vous pouvez utiliser les mots-clés suivants :

- `bug`
- `defect`
- `rtcwi`
- `task`
- `work item`
- `workitem`

Évitez d'utiliser le mot-clé `#`. Pour plus d'informations, consultez [Création de liens à partir de commentaires de commit](https://www.ibm.com/docs/en/elm/7.0.0?topic=commits-creating-links-from-commit-comments).
