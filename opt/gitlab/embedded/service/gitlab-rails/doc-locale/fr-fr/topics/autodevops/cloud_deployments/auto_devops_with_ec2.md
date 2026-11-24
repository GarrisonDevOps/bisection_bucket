---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Utiliser Auto DevOps pour déployer sur EC2
---

Pour utiliser [Auto DevOps](../_index.md) afin de déployer sur EC2 :

1. Définissez [vos identifiants AWS en tant que variables CI/CD](../../../ci/cloud_deployment/_index.md#authenticate-gitlab-with-aws).
1. Dans votre fichier `.gitlab-ci.yml`, référencez le modèle `Auto-Devops.gitlab-ci.yml`.
1. Définissez un job pour l'étape `build` nommé `build_artifact`. Par exemple :

   ```yaml
   # .gitlab-ci.yml

   include:
     - template: Auto-DevOps.gitlab-ci.yml

   variables:
     AUTO_DEVOPS_PLATFORM_TARGET: EC2

   build_artifact:
     stage: build
     script:
       - <your build script goes here>
     artifacts:
       paths:
         - <built artifact>
   ```

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une présentation vidéo de ce processus, visionnez [Auto Deploy to EC2](https://www.youtube.com/watch?v=4B-qSwKnacA).
