---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Convertir une instance Docker CE en EE
---

Vous pouvez convertir un conteneur Docker GitLab Community Edition (CE) existant en conteneur GitLab [Enterprise Edition](https://about.gitlab.com/pricing/) (EE) en utilisant la même approche que pour [la mise à niveau de version](../docker/_index.md).

Vous devriez convertir depuis la même version de CE vers EE (par exemple, CE 18.1 vers EE 18.1). Cependant, cela n'est pas obligatoire. Toute mise à niveau standard (par exemple, CE 18.0 vers EE 18.1) devrait fonctionner. Les étapes suivantes supposent que vous effectuez une conversion vers la même version.

1. Effectuez une [sauvegarde](../../install/docker/backup.md). Au minimum, sauvegardez [la base de données](../../install/docker/backup.md#create-a-database-backup) et le fichier des secrets GitLab.
1. Arrêtez le conteneur CE actuel, puis supprimez-le ou renommez-le.
1. Pour créer un nouveau conteneur avec GitLab EE, remplacez `ce` par `ee` dans votre commande `docker run` ou votre fichier `docker-compose.yml`. Réutilisez le nom du conteneur CE, les mappages de ports, les mappages de fichiers et la version.
