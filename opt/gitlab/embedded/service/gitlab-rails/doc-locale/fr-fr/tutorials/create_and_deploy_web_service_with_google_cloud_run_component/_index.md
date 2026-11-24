---
stage: Verify
group: tutorials
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 'Tutoriel : créer et déployer un service web avec le composant Google Cloud Run'
---

Découvrez comment utiliser le [composant Google Cloud Run](https://gitlab.com/google-gitlab-components/cloud-run) pour déployer un service web à partir d'une image de conteneur stockée dans Artifact Registry.

## Avant de commencer {#before-you-begin}

1. Suivez les instructions dans [Configurer l'intégration Google Cloud](../set_up_gitlab_google_integration/_index.md) pour :

   - Configurer Google Cloud IAM.
   - Connecter GitLab à Google Artifact Registry.
   - Configurer GitLab Runner pour exécuter vos jobs CI/CD sur Google Cloud.

1. Pour exécuter les commandes sur cette page, configurez l'interface de ligne de commande `gcloud` dans l'un des environnements de développement suivants :

   - [Cloud Shell](https://docs.cloud.google.com/shell/docs/using-cloud-shell)
   - [Shell local](https://cloud.google.com/sdk/docs/install)

1. Définissez votre projet Google Cloud par défaut en exécutant la commande suivante :

   ```shell
   gcloud config set project PROJECT_ID
   ```

   Une fois votre projet par défaut défini, vous n'avez plus besoin de passer l'indicateur `--project` avec les commandes `gcloud`.
1. Activez les API Compute Engine et Cloud Run :

   ```shell
   gcloud services enable compute.googleapis.com artifactregistry.googleapis.com run.googleapis.com
   ```

1. Accordez les rôles suivants à votre pool d'identités de charge de travail :

   - Cloud Storage Admin (`roles/run.admin`) pour obtenir, créer et mettre à jour un service.
   - Utilisateurs de compte de service (`roles/iam.serviceAccountUser`) pour exécuter des opérations en tant que compte de service

   Exécutez les commandes suivantes pour accorder les rôles `roles/run.admin` et `roles/iam.serviceAccountUser` à tous les principaux de votre pool d'identités de charge de travail correspondant au mappage d'attributs `developer_access=true` :

   ```shell
   # Replace ${PROJECT_ID}, ${PROJECT_NUMBER}, ${LOCATION}, ${POOL_ID} with your values below
   WORKLOAD_IDENTITY=principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/${POOL_ID}/attribute.developer_access/true
   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="${WORKLOAD_IDENTITY}" --role="roles/run.admin"
   gcloud projects add-iam-policy-binding ${PROJECT_ID} --member="${WORKLOAD_IDENTITY}" --role="roles/iam.serviceAccountUser"
   ```

## Configurer l'intégration IAM dans un nouveau projet GitLab {#configure-the-iam-integration-in-a-new-gitlab-project}

Une fois que vous avez configuré Google IAM pour l'intégration pour votre organisation ou votre groupe, vous pouvez réutiliser l'intégration dans de nouveaux projets de cette organisation ou de ce groupe :

1. [Créez un nouveau projet GitLab](../../user/project/_index.md) dans votre organisation ou votre groupe.
1. Dans votre projet GitLab, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Google Cloud IAM**.
1. Dans la section **Projet Google Cloud**, saisissez les informations suivantes :

   - **ID du projet** : l'ID de projet Google Cloud pour votre pool d'identités de charge de travail
   - **Numéro du projet** : le numéro de projet Google Cloud pour le même projet

   Pour trouver l'ID et le numéro du projet Google Cloud, consultez [Identification des projets](https://cloud.google.com/resource-manager/docs/creating-managing-projects#identifying_projects).

1. Dans la section **Fédération d'identité de charge de travail**, saisissez les informations suivantes :

   - **ID du pool** : le nom que vous avez donné à votre pool d'identités de charge de travail.
   - **ID du fournisseur** : le nom que vous avez donné à votre fournisseur OIDC.

   Conseil : vous pouvez copier ces valeurs depuis le projet GitLab que vous avez initialement utilisé pour configurer l'intégration.

1. Sélectionnez **Enregistrer les modifications**. N'exécutez pas le script fourni, car il crée un pool d'identités de charge de travail, et vous en avez déjà un.

## Configurer l'intégration Google Artifact Registry dans un nouveau projet GitLab {#configure-the-google-artifact-registry-integration-in-a-new-gitlab-project}

Vous pouvez stocker plusieurs images de conteneurs dans Artifact Registry. Pour réutiliser le même dépôt pour un nouveau projet GitLab, configurez l'intégration Google Artifact Management dans votre projet.

1. Dans votre projet GitLab, sélectionnez **Paramètres** > **Intégrations**.
1. Sélectionnez **Gestion des artefacts Google**
1. Dans la section **Dépôt**, saisissez les informations suivantes :

   - **ID de projet Google Cloud** : l'ID du projet pour le dépôt Artifact Registry que vous souhaitez utiliser
   - **Nom du dépôt** : le nom du dépôt
   - **Emplacement du dépôt** : l'emplacement de votre dépôt

1. Sélectionnez **Enregistrer les modifications**. N'exécutez pas le script fourni, car votre pool d'identités de charge de travail accorde déjà aux utilisateurs GitLab de votre groupe ou organisation le rôle de lecteur et d'auteur Artifact Registry.

## Cloner votre dépôt GitLab {#clone-your-gitlab-repository}

Pour utiliser SSH ou HTTPS afin de cloner votre dépôt GitLab dans votre environnement de travail, suivez les instructions dans [Cloner un dépôt Git sur votre ordinateur local](../../topics/git/clone.md).

## Créer un Dockerfile {#create-a-dockerfile}

1. Dans votre dépôt cloné, créez un nouveau fichier nommé `Dockerfile`.
1. Copiez et collez le contenu suivant dans votre `Dockerfile` :

   ```dockerfile
   FROM python:3.12.4

   ARG name

   RUN mkdir web

   RUN cat <<EOF > web/index.html
   <!DOCTYPE html>
   <html>
       <head>
           <title>Home</title>
       </head>
       <body>
           <h1 color="green">Welcome to $name</h1>
       </body>
   </html>
   EOF

   CMD ["python3", "-m", "http.server", "8080", "-d", "web"]
   ```

1. Ajoutez votre `Dockerfile` à Git, effectuez un commit et poussez vers votre dépôt GitLab :

   ```shell
   git add Dockerfile
   git commit -m "add dockerfile"
   git push
   ```

   Vous êtes invité à saisir votre nom d'utilisateur et votre [jeton d'accès personnel](../../user/profile/personal_access_tokens.md).

Le Dockerfile crée un service web HTTP.

## Créer un pipeline {#create-a-pipeline}

Créez un pipeline qui construit votre image Docker, la pousse vers le registre de conteneurs GitLab, copie l'image dans Google Artifact Registry et utilise Cloud Run pour déployer sur l'infrastructure Google Cloud.

1. Dans votre projet GitLab, créez un [fichier `.gitlab-ci.yml`](../../ci/quick_start/_index.md#create-a-gitlab-ciyml-file).
1. Pour créer un pipeline qui construit votre image, la pousse vers le registre de conteneurs GitLab, la copie dans Google Artifact Registry et utilise Cloud Run pour déployer, modifiez le contenu de votre fichier `.gitlab-ci.yml` pour qu'il ressemble à ce qui suit.

   Dans l'exemple suivant, remplacez les éléments suivants :

   - `LOCATION` : la région Google Cloud où vous avez créé votre dépôt Google Artifact Registry.
   - `PROJECT` : votre ID de projet Google Cloud pour votre dépôt Artifact Registry.
   - `REPOSITORY` : l'ID du dépôt de votre dépôt Google Artifact Registry.

   ```yaml
   variables:
     IMAGE_TAG: v$CI_PIPELINE_ID
     AR_IMAGE: LOCATION-docker.pkg.dev/PROJECT/REPOSITORY/python-service

   stages:
     - build
     - push
     - deploy

   build-job:
     stage: build
     services:
       - docker:24.0.5-dind
     image: docker:git
     before_script:
       - docker login -u $CI_REGISTRY_USER -p $CI_REGISTRY_PASSWORD $CI_REGISTRY
     script:
       - docker build -t $CI_REGISTRY_IMAGE:$IMAGE_TAG --build-arg="name=Cloud Run" .
       - docker push $CI_REGISTRY_IMAGE:$IMAGE_TAG

   include:
     - component: gitlab.com/google-gitlab-components/artifact-registry/upload-artifact-registry@0.1.0
       inputs:
         stage: push
         source: $CI_REGISTRY_IMAGE:$IMAGE_TAG
         target: $AR_IMAGE:$IMAGE_TAG

     - component: gitlab.com/google-gitlab-components/cloud-run/deploy-cloud-run@0.1.0
       inputs:
         stage: deploy
         image: $AR_IMAGE:$IMAGE_TAG
         project_id: PROJECT
         region: LOCATION
         service: python-service

   ```

1. Ajoutez votre fichier `.gitlab-ci.yml` à Git, effectuez un commit et poussez vers votre dépôt GitLab.

Le pipeline effectue les opérations suivantes :

- Construit l'image `python-service` avec Docker-in-Docker.
- Stocke l'image dans le registre de conteneurs GitLab.
- Pousse l'image vers Google Artifact Registry avec le [composant GitLab Google Artifact Registry](https://gitlab.com/explore/catalog/google-gitlab-components/artifact-registry).
- Déploie `python-service` avec le [composant Google Cloud Run](https://gitlab.com/google-gitlab-components/cloud-run).

## Afficher votre service dans Google Cloud Run {#view-your-service-in-google-cloud-run}

1. Dans la console Google Cloud, accédez à la [page Cloud Run](https://console.cloud.google.com/run).
1. Sélectionnez le service que vous avez créé dans l'onglet **Services**.

   L'onglet **Métriques** du service s'affiche et vous pouvez consulter la région, l'URL et d'autres détails du service.

## Utiliser un proxy pour afficher votre service {#proxy-your-service-to-view}

Le service est privé, vous ne pouvez donc pas l'afficher depuis l'URL indiquée dans la console Google Cloud sans vous authentifier. Pour tester le service, vous pouvez utiliser l'interface de ligne de commande `gcloud` pour vous authentifier et utiliser un proxy pour le service vers `http://localhost:8080`.

Exécutez la commande suivante pour utiliser un proxy pour votre service en local :

```shell
gcloud run services proxy SERVICE \
    --project PROJECT_ID \
    --region=LOCATION
```

Vous pouvez afficher la page d'accueil à l'adresse `http://localhost:8080`.

## Nettoyage {#clean-up}

Pour éviter des frais sur votre compte Google Cloud liés aux ressources utilisées sur cette page, vous pouvez supprimer vos ressources Google Cloud ou l'intégralité de votre projet Google Cloud.

Si vous supprimez le projet contenant votre pool d'identités de charge de travail, vous ne pourrez pas utiliser l'intégration à moins de suivre à nouveau toutes les instructions de configuration.

Pour obtenir des informations sur les tarifs GitLab et Google ainsi que sur la gestion de projet, consultez les ressources suivantes :

- [Tarification GitLab](https://about.gitlab.com/free-trial/devsecops/)
- [Tarification Google](https://cloud.google.com/pricing)
- [Supprimer un projet GitLab](../../user/project/working_with_projects.md#delete-a-project)

### Supprimer votre dépôt Google Artifact Registry {#delete-your-google-artifact-registry-repository}

Pour supprimer votre dépôt Google Artifact Registry, suivez les étapes de cette section. Si vous souhaitez supprimer l'intégralité de votre projet Google Cloud, suivez les étapes dans [Supprimer votre projet](#delete-your-google-cloud-project).

Avant de supprimer le dépôt, assurez-vous que les images que vous souhaitez conserver sont disponibles dans un autre emplacement.

Pour supprimer votre dépôt, exécutez la commande suivante :

```shell
gcloud artifacts repositories delete REPOSITORY \
    --location=LOCATION
```

Remplacez les éléments suivants :

- `REPOSITORY` par l'ID de votre dépôt Google Artifact Registry
- `LOCATION` par l'emplacement de votre dépôt

### Supprimer votre service Cloud Run {#delete-your-cloud-run-service}

1. Dans la console Google Cloud, accédez à la [page Cloud Run](https://console.cloud.google.com/run).
1. Cochez la case en regard de votre service.
1. Sélectionnez **Supprimer**.

### Supprimer votre projet Google Cloud {#delete-your-google-cloud-project}

**Attention** : la suppression d'un projet a les effets suivants :

- Tout le contenu du projet est supprimé. Si vous avez utilisé un projet existant pour les tâches de ce document, sa suppression entraîne également la suppression de tout autre travail effectué dans ce projet.
- Les ID de projet personnalisés sont perdus. Lors de la création de ce projet, vous avez peut-être créé un ID de projet personnalisé que vous souhaitez utiliser à l'avenir. Pour préserver les URL qui utilisent l'ID du projet, comme une URL appspot.com, supprimez les ressources sélectionnées dans le projet plutôt que de supprimer l'intégralité du projet.

Si vous prévoyez d'explorer plusieurs architectures, tutoriels ou tutoriels de démarrage rapide sur Google Cloud, la réutilisation des projets peut vous aider à éviter de dépasser les limites de quota de projet.

1. Dans la console Google Cloud, accédez à la [page **Gérer les ressources**](https://console.cloud.google.com/iam-admin/projects).
1. Dans la liste des projets, sélectionnez le projet que vous souhaitez supprimer, puis sélectionnez **Supprimer**.
1. Dans la boîte de dialogue, saisissez l'ID du projet, puis sélectionnez **Arrêter** pour supprimer le projet.

## Sujets connexes {#related-topics}

- [En savoir plus sur Cloud Run](https://docs.cloud.google.com/run/docs/overview/what-is-cloud-run).
