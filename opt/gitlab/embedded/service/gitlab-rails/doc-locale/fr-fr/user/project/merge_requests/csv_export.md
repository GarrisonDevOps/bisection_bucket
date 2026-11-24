---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Exporter les merge requests en CSV
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Exportez toutes les données collectées à partir des merge requests d'un projet dans un fichier de valeurs séparées par des virgules (CSV).

Pour exporter des merge requests dans un fichier CSV :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**.
1. Ajoutez des recherches ou des filtres. Cela peut vous aider à maintenir la taille du fichier CSV en dessous de la limite de 15 Mo. Cette limite garantit que le fichier peut être envoyé par e-mail à différents fournisseurs de messagerie.
1. Sélectionnez **Actions** ({{< icon name="ellipsis_v" >}}) > **Exporter au format CSV**.
1. Confirmez que le nombre de merge requests à exporter est correct.
1. Sélectionnez **Exporter les requêtes de fusion**.

## Sortie CSV {#csv-output}

Le tableau suivant présente les attributs du fichier CSV.

| Colonne             | Description                                                  |
|--------------------|--------------------------------------------------------------|
| Titre              | Titre de la merge request                                          |
| Description        | Description de la merge request                                    |
| ID de la MR              | `iid` de la merge request                                                     |
| URL                | Un lien vers la merge request sur GitLab                        |
| État              | Ouverte, Fermée, Verrouillée ou Fusionnée                            |
| Branche source      | Branche source                                                |
| Branche cible      | Branche cible                                                |
| ID du projet source  | ID du projet source                                     |
| ID du projet cible  | ID du projet cible                                     |
| Auteur             | Nom complet de l'auteur de la merge request                        |
| Nom d'utilisateur de l'auteur    | Nom d'utilisateur de l'auteur, sans le symbole @            |
| Personnes assignées          | Noms complets des personnes assignées à la merge request, joints par un `,` |
| Noms d'utilisateur des personnes assignées | Noms d'utilisateur des personnes assignées, sans le symbole @         |
| Approbateurs          | Noms complets des approbateurs, joints par un `,`               |
| Noms d'utilisateur des approbateurs | Noms d'utilisateur des approbateurs, sans le symbole @         |
| Utilisateur ayant fusionné        | Nom complet de l'utilisateur ayant fusionné                                 |
| Nom d'utilisateur de la personne ayant fusionné    | Nom d'utilisateur de la personne ayant fusionné, sans le symbole @        |
| ID du jalon       | ID du jalon de la merge request                            |
| Date de création (UTC)   | Formaté comme `YYYY-MM-DD HH:MM:SS`                           |
| Mis à jour le (UTC)   | Formaté comme `YYYY-MM-DD HH:MM:SS`                           |
