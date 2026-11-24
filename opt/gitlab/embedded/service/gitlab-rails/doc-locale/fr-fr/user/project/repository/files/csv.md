---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Affichage des fichiers CSV (valeurs séparées par des virgules) dans les projets GitLab.
title: Fichiers CSV
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Un fichier CSV (comma-separated values, ou valeurs séparées par des virgules) est un fichier texte délimité qui utilise une virgule pour séparer les valeurs. Chaque ligne du fichier constitue un enregistrement de données. Chaque enregistrement est composé d'un ou plusieurs champs, séparés par des virgules. L'utilisation de la virgule comme séparateur de champs est à l'origine du nom de ce format de fichier. Un fichier CSV stocke généralement des données tabulaires (nombres et texte) en texte brut, auquel cas chaque ligne comporte le même nombre de champs.

Le format de fichier CSV n'est pas entièrement standardisé. D'autres caractères peuvent être utilisés comme délimiteurs de colonnes. Les champs peuvent ou non être encadrés pour échapper les caractères spéciaux.

Lorsqu'ils sont ajoutés à un dépôt, les fichiers avec une extension `.csv` sont affichés sous forme de tableau dans GitLab :

![Fichier CSV affiché sous forme de tableau](img/csv_as_table_v17_10.png)

## Considérations relatives à l'analyse CSV {#csv-parsing-considerations}

GitLab utilise la bibliothèque [Papa Parse](https://github.com/mholt/PapaParse/) pour analyser les fichiers CSV. Cette bibliothèque suit la [RFC4180](https://datatracker.ietf.org/doc/html/rfc4180) et impose des exigences de formatage strictes qui peuvent entraîner des problèmes d'analyse avec certains formats CSV.

Par exemple :

- Les espaces autour des séparateurs virgule (`,`) et des guillemets doubles (`"`) peuvent provoquer des erreurs d'analyse.
- Les champs contenant à la fois des virgules et des guillemets doubles peuvent amener l'analyseur à mal identifier les limites des champs.

Le format suivant provoque des erreurs d'analyse :

```plaintext
"field1", "field2", "field3"
```

Le format suivant est analysé avec succès :

```plaintext
"field1","field2","field3"
```

Si votre fichier CSV ne s'affiche pas correctement dans GitLab :

- Si les champs sont délimités par des guillemets doubles (`"`), assurez-vous que les guillemets doubles et les séparateurs virgule (`,`) sont immédiatement adjacents, sans espace entre eux.
- Entourez de guillemets doubles (`"`) tous les champs contenant des caractères spéciaux.
- Testez l'affichage du fichier CSV dans GitLab après avoir apporté des modifications.

Ces exigences d'analyse n'affectent que le rendu visuel des fichiers CSV et n'ont aucun impact sur le contenu réel des fichiers stockés dans votre dépôt.
