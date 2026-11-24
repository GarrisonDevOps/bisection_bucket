---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Utiliser Auto DevOps pour déployer sur Amazon ECS
---

Vous pouvez choisir de cibler AWS ECS comme plateforme de déploiement au lieu d'utiliser Kubernetes.

Pour commencer à utiliser Auto DevOps avec AWS ECS, vous devez ajouter une variable CI/CD spécifique. Pour ce faire, suivez ces étapes :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Auto DevOps**.
1. Spécifiez la plateforme AWS à cibler lors du déploiement Auto DevOps en ajoutant la variable `AUTO_DEVOPS_PLATFORM_TARGET` avec l'une des valeurs suivantes  :
   - `FARGATE` si le service que vous ciblez doit être de type de lancement FARGATE.
   - `ECS` si vous n'imposez aucune vérification du type de lancement lors du déploiement sur ECS.

Lorsque vous déclenchez un pipeline, si Auto DevOps est activé et si vous avez correctement [saisi les identifiants AWS en tant que variables](../../../ci/cloud_deployment/_index.md#authenticate-gitlab-with-aws), votre application est déployée sur AWS ECS.

Si vous disposez à la fois d'une variable `AUTO_DEVOPS_PLATFORM_TARGET` valide et d'un cluster Kubernetes associé à votre projet, seul le déploiement sur Kubernetes s'exécute.

> [!warning]
> La définition de la variable `AUTO_DEVOPS_PLATFORM_TARGET` sur `ECS` déclenche des jobs définis dans le [modèle `Jobs/Deploy/ECS.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Jobs/Deploy/ECS.gitlab-ci.yml). Cependant, il n'est pas recommandé de l'[inclure](../../../ci/yaml/_index.md#includetemplate) seul. Ce modèle est conçu pour être utilisé uniquement avec Auto DevOps. Il peut changer de manière inattendue et entraîner l'échec de votre pipeline s'il est inclus seul. De plus, les noms des jobs dans ce modèle sont également susceptibles de changer. Ne remplacez pas les noms de ces jobs dans votre propre pipeline, car le remplacement cesse de fonctionner lorsque le nom change.
