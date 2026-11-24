---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Comment les fichiers GeoJSON sont rendus lors de leur affichage dans les projets GitLab.
title: Fichiers GeoJSON
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Un fichier GeoJSON est un format d'encodage de structures de données géographiques utilisant la notation JavaScript Object Notation (JSON). Il est couramment utilisé pour représenter des entités géographiques, telles que des points, des lignes et des polygones, ainsi que leurs attributs associés.

Lorsqu'ils sont ajoutés à un dépôt, les fichiers avec l'extension `.geojson` sont rendus sous forme de carte contenant les données GeoJSON lors de leur affichage dans GitLab.

Les données cartographiques proviennent de [OpenStreetMap](https://www.openstreetmap.org/) sous la [Open Database License](https://www.openstreetmap.org/copyright).

![Fichier GeoJSON rendu sous forme de carte](img/geo_json_file_rendered_v16_1.png)
