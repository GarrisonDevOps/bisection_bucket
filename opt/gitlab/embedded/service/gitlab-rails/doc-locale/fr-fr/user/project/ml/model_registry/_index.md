---
stage: ModelOps
group: MLOps
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Registre de modèles
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/9423) dans GitLab 16.8 en tant que release [version expérimentale](../../../../policy/development_stages_support.md#experiment) [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `model_registry`. Fonctionnalité désactivée par défaut. Pour activer la fonctionnalité, un administrateur peut [activer le feature flag](../../../../administration/feature_flags/_index.md) nommé `model_registry`.
- [Passage](https://gitlab.com/groups/gitlab-org/-/work_items/9423) en version bêta dans GitLab 17.1.
- [Passage](https://gitlab.com/groups/gitlab-org/-/epics/14998) en disponibilité générale dans GitLab 17.6.

{{< /history >}}

Un registre de modèles de machine learning sert de dépôt centralisé pour gérer les modèles de machine learning tout au long de leur cycle de vie. Il fonctionne comme une base de données spécialisée qui stocke les versions de modèles ainsi que les métadonnées essentielles, notamment les métriques de performance, les résultats de validation et les informations sur la traçabilité des données.

Utilisez les registres de modèles GitLab pour :

- Enregistrer et versionner les modèles de machine learning de manière systématique
- Suivre des métadonnées complètes incluant les métriques de performance, les paramètres et la traçabilité des données
- Comparer les versions de modèles et surveiller leur évolution dans le temps
- Maintenir une documentation claire du comportement et des exigences des modèles

Pour plus d'informations sur les fonctionnalités et les capacités du registre de modèles, consultez [l'epic 9423](https://gitlab.com/groups/gitlab-org/-/work_items/9423).

## Accéder au registre de modèles {#access-the-model-registry}

Le registre de modèles est contrôlé par le paramètre du registre de paquets. Avant d'utiliser le registre de modèles, assurez-vous que le [registre de paquets est activé](../../../../administration/packages/_index.md#enable-or-disable-the-package-registry).

Pour accéder au registre de modèles, dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de modèles**.

Si **Registre de modèles** n'est pas disponible, assurez-vous qu'il a été activé.

Pour activer le registre de modèles ou définir le [niveau de visibilité](../../../public_access.md) sur public ou privé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Visibilité, fonctionnalités du projet, autorisations**.
1. Sous **Registre de modèles**, assurez-vous que le bouton est activé et sélectionnez les personnes auxquelles vous souhaitez accorder l'accès. Les utilisateurs doivent disposer au minimum du [rôle Reporter](../../../permissions.md#roles) pour modifier ou supprimer des modèles et des versions de modèles.

## Créer des modèles de machine learning à l'aide de l'interface utilisateur {#create-machine-learning-models-by-using-the-ui}

Pour créer un nouveau modèle de machine learning à l'aide de l'interface utilisateur GitLab :

1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de modèles**.
1. Sur la page **Registre de modèles**, vous pouvez :
   - Sélectionnez **Créer un modèle** si vous n'avez pas encore de modèles.
   - Dans le coin supérieur droit, sélectionnez **Créer/Importer un modèle**, puis sélectionnez **Créer un nouveau modèle** dans la liste déroulante.
1. Remplissez les champs :
   - Saisissez un nom unique pour votre modèle.
   - Facultatif. Fournissez une description pour le modèle.
1. Sélectionnez **Créer**.

Vous pouvez maintenant afficher le modèle nouvellement créé dans le registre de modèles.

## Créer une version de modèle à l'aide de l'interface utilisateur {#create-a-model-version-by-using-the-ui}

Pour créer une nouvelle version de modèle :

1. Sur la page des détails du modèle, sélectionnez **Créer une nouvelle version**.
1. Remplissez les champs :
   - Saisissez un numéro de version unique en suivant la gestion sémantique de version.
   - Facultatif. Fournissez une description pour la version du modèle.
   - Téléversez tous les fichiers, journaux, métriques ou paramètres associés à la version du modèle.
1. Sélectionnez **Créer et importer**.

La nouvelle version du modèle est désormais disponible dans le registre de modèles.

### Supprimer un modèle {#delete-a-model}

Pour supprimer un modèle et toutes ses versions associées :

1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de modèles**.
1. Trouvez le modèle que vous souhaitez supprimer.
1. Dans la colonne la plus à droite, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) et **Supprimer le modèle**.

Vous pouvez également supprimer des modèles depuis la page des détails du modèle :

1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de modèles**.
1. Trouvez le modèle que vous souhaitez supprimer.
1. Sélectionnez le nom du modèle pour afficher ses détails.
1. Sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) et **Supprimer le modèle**.
1. Confirmez la suppression.

### Supprimer une version de modèle {#delete-a-model-version}

Pour supprimer une version de modèle :

1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de modèles**.
1. Trouvez le modèle dont vous souhaitez supprimer une version.
1. Sélectionnez le nom du modèle pour afficher ses détails.
1. Sélectionnez l'onglet **Versions**.
1. Trouvez la version du modèle que vous souhaitez supprimer.
1. Dans la colonne la plus à droite, sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) et **Supprimer une version**.

Vous pouvez également supprimer des modèles depuis la page des détails de la version du modèle :

1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de modèles**.
1. Trouvez le modèle dont vous souhaitez supprimer une version.
1. Sélectionnez le nom du modèle pour afficher ses détails.
1. Sélectionnez l'onglet **Versions**.
1. Sélectionnez le nom de la version pour afficher ses détails.
1. Sélectionnez les points de suspension verticaux ({{< icon name="ellipsis_v" >}}) et **Supprimer une version**.
1. Confirmez la suppression.

### Ajouter des artéfacts à une version de modèle {#add-artifacts-to-a-model-version}

Pour ajouter des artéfacts à une version de modèle :

1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de modèles**.
1. Trouvez le modèle.
1. Sélectionnez le nom du modèle pour afficher ses détails.
1. Sélectionnez l'onglet **Versions**.
1. Sélectionnez le nom de la version pour afficher ses détails.
1. Sélectionnez l'onglet **Artéfacts**.
1. Facultatif. Spécifiez un chemin de sous-dossier pour les fichiers à téléverser. Par exemple `config`.
1. Utilisez **sélectionner** pour choisir les fichiers à téléverser.
1. Sélectionnez **Téléversement**.

Vous pouvez également faire glisser et déposer des fichiers dans la zone de dépôt. Les artéfacts sont automatiquement téléversés.

Chaque fichier étant limité à 5 Go, vous devez partitionner les modèles plus volumineux.

### Supprimer des artéfacts d'une version de modèle {#delete-artifacts-from-a-model-version}

Pour supprimer les artéfacts d'une version :

1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Registre de modèles**.
1. Trouvez le modèle.
1. Sélectionnez le nom du modèle pour afficher ses détails.
1. Sélectionnez l'onglet **Versions**.
1. Sélectionnez le nom de la version pour afficher ses détails.
1. Sélectionnez l'onglet **Artéfacts**.
1. Cochez la case à côté de chaque artéfact que vous souhaitez supprimer.
1. Sélectionnez **Supprimer**.
1. Confirmez la suppression.

## Créer des modèles de machine learning et des versions de modèles à l'aide de MLflow {#create-machine-learning-models-and-model-versions-by-using-mlflow}

Les modèles et les versions de modèles peuvent être créés à l'aide de la compatibilité client [MLflow](https://www.mlflow.org/docs/latest/tracking.html). Pour plus d'informations sur la création et la gestion des modèles et des versions de modèles, consultez la [compatibilité client MLflow](../experiment_tracking/mlflow_client.md#model-registry). Vous pouvez également créer des modèles directement sur GitLab en sélectionnant **Créer un modèle** sur la page du registre de modèles.

### Ajouter des artéfacts, des métriques et des paramètres à une version de modèle à l'aide de MLflow {#add-artifacts-metrics-and-parameters-to-a-model-version-by-using-mlflow}

Les fichiers peuvent être téléversés vers une version de modèle de deux façons :

- Le registre de paquets, où une version de modèle est associée à un paquet portant le nom `<model_name>/<model_version>`.
- La compatibilité client MLflow. [Voir les détails](../experiment_tracking/mlflow_client.md#logging-artifacts-to-a-model-version).

Les utilisateurs peuvent enregistrer les métriques et les paramètres d'une version de modèle via la compatibilité client MLflow. [Voir les détails](../experiment_tracking/mlflow_client.md#logging-metrics-and-parameters-to-a-model-version).

## Associer une version de modèle à un job CI/CD {#link-a-model-version-to-a-cicd-job}

Lors de la création d'une version de modèle via un job GitLab CI/CD, vous pouvez associer la version du modèle au job, ce qui donne un accès pratique aux journaux du job, à la merge request et au pipeline. Cette opération peut être effectuée via la compatibilité client MLflow. [Voir les détails](../experiment_tracking/mlflow_client.md#linking-a-model-version-to-a-cicd-job).

## Versions de modèles et gestion sémantique de version {#model-versions-and-semantic-versioning}

La version d'une version de modèle dans GitLab doit suivre la [spécification de gestion sémantique de version](https://semver.org/). L'utilisation de la gestion sémantique de version facilite le déploiement des modèles, en indiquant si une nouvelle version peut être déployée sans modification de l'application :

- **Majeure (entier)** : une modification du composant majeur signifie un changement de rupture dans le modèle, et que l'application qui utilise le modèle doit être mise à jour pour utiliser correctement cette nouvelle version. Un nouvel algorithme ou l'ajout d'une colonne de fonctionnalité obligatoire sont des exemples de changements de rupture qui nécessiteraient une incrémentation du composant majeur.

- **Mineure (entier)** : une modification du composant mineur signifie un changement non-rompu, et que le consommateur peut utiliser la nouvelle version en toute sécurité sans rupture, bien que le consommateur puisse avoir besoin d'être mis à jour pour utiliser ses nouvelles fonctionnalités. Par exemple, l'ajout d'une colonne de fonctionnalité non obligatoire avec une valeur par défaut au modèle est une incrémentation mineure, car lorsqu'aucune valeur n'est transmise pour la colonne ajoutée, l'inférence fonctionne toujours.

- **Correctif (entier)** : une modification du composant correctif signifie qu'une nouvelle version est disponible et ne nécessite aucune action de la part de l'application. Par exemple, un réentraînement quotidien du modèle ne modifie pas l'ensemble de fonctionnalités ni la façon dont l'application utilise la version du modèle. La mise à jour automatique vers un nouveau correctif est une mise à jour sûre.

- **Préversion (texte)** : représente une version qui n'est pas encore prête pour une utilisation en production. Utilisé pour identifier les versions alpha, bêta ou les versions candidates à la release du modèle.

### Exemples de versions de modèles {#model-version-examples}

- Version initiale : 1.0.0 - La première release du modèle, sans modification ni correctif.
- Nouvelle fonctionnalité : 1.1.0 - Une nouvelle fonctionnalité non-rompue a été ajoutée au modèle, incrémentant la version mineure.
- Correction de bug : 1.1.1 - Un bug a été corrigé dans le modèle, incrémentant la version de correctif.
- Changement de rupture : 2.0.0 - Un changement de rupture a été apporté au modèle, incrémentant la version majeure.
- Release de correctif : 2.0.1 - Un bug a été corrigé dans le modèle, incrémentant la version de correctif.
- Préversion : 2.0.1-alpha1 - Une préversion du modèle, avec une release alpha.
- Préversion : 2.0.1-rc2 - Une version candidate à la release du modèle.
- Nouvelle fonctionnalité : 2.1.0 - Une nouvelle fonctionnalité a été ajoutée au modèle, la version mineure est donc incrémentée.
