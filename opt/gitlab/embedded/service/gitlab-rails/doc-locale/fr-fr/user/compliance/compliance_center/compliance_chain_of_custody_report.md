---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Générez et exportez le rapport sur la chaîne de possession dans GitLab pour suivre les modifications de projet et les détails de fusion à des fins de conformité.
title: Rapport sur la chaîne de possession
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Le rapport sur la chaîne de possession fournit une fenêtre glissante d'un mois de tous les commits d'un projet au sein du groupe.

Pour générer le rapport pour tous les commits, GitLab :

1. Récupère tous les projets du groupe.
1. Pour chaque projet, récupère le dernier mois de commits dans l'ordre chronologique (du plus récent au plus ancien). Chaque projet est limité à 1024 commits. Si la fenêtre d'un mois contient plus de 1024 commits, ils sont tronqués.
1. Trie tous les commits par date de commit (ordre décroissant) avec un tri secondaire déterministe par SHA de commit pour un ordonnancement cohérent.
1. Écrit les commits dans un fichier CSV. Le fichier est tronqué à 15 Mo car le rapport est envoyé par e-mail en pièce jointe.

Le rapport comprend :

- SHA du commit.
- Auteur du commit.
- Auteur de la validation (normalisé en nom d'utilisateur GitLab lorsque disponible, sur la base de l'e-mail de l'auteur de la validation).
- Date de commit (avec une précision à la milliseconde au format UTC).
- Groupe.
- Projet.

Si le commit est associé à un commit de fusion, les éléments suivants sont également inclus :

- SHA du commit de fusion.
- ID de la merge request.
- Utilisateur ayant fusionné la merge request.
- Date de fusion.
- ID du pipeline.
- Approbateurs de la merge request.

## Générer le rapport sur la chaîne de possession {#generate-chain-of-custody-report}

Pour générer le rapport sur la chaîne de possession :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Dans le coin supérieur droit, sélectionnez **Exporter**.
1. Sélectionnez **Exporter le rapport sur la chaîne de possession**.

Le rapport sur la chaîne de possession est envoyé par e-mail.

## Générer le rapport sur la chaîne de possession spécifique à un commit {#generate-commit-specific-chain-of-custody-report}

Vous pouvez générer un rapport sur la chaîne de possession spécifique à un commit pour un SHA de commit donné. Ce rapport fournit uniquement les détails relatifs au SHA de commit fourni.

Pour générer un rapport sur la chaîne de possession spécifique à un commit :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Sécuriser** > **Centre de conformité**.
1. Dans le coin supérieur droit, sélectionnez **Exporter**.
1. Sélectionnez **Exporter le rapport de possession d'une validation spécifique**.
1. Saisissez le SHA du commit, puis sélectionnez **Exporter le rapport de possession**.

Le rapport sur la chaîne de possession est envoyé par e-mail.

Vous pouvez également utiliser un lien direct : `https://gitlab.com/groups/<group-name>/-/security/merge_commit_reports.csv?commit_sha={optional_commit_sha}`, en transmettant une valeur facultative au paramètre de requête `commit_sha`.
