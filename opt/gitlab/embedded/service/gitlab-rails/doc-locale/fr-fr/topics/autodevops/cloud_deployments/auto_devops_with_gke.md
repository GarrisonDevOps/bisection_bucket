---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Utiliser Auto DevOps pour déployer une application sur Google Kubernetes Engine
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Ce tutoriel vous permet de démarrer avec [Auto DevOps](../_index.md) en vous montrant comment déployer une application sur Google Kubernetes Engine (GKE).

Vous utilisez l'intégration Kubernetes native de GitLab, ce qui vous évite de créer manuellement un cluster Kubernetes à l'aide de la console Google Cloud Platform. Vous créez et déployez une application à partir d'un modèle GitLab.

Ces instructions fonctionnent également pour GitLab Self-Managed. Assurez-vous que vos [runners sont configurés](../../../ci/runners/_index.md) et que [Google OAuth est activé](../../../integration/google.md).

Pour déployer un projet sur Google Kubernetes Engine, suivez les étapes ci-dessous :

1. [Configurer votre compte Google](#configure-your-google-account)
1. [Créer un cluster Kubernetes et déployer l'agent](#create-a-kubernetes-cluster)
1. [Créer un nouveau projet à partir d'un modèle](#create-an-application-project-from-a-template)
1. [Configurer l'agent](#configure-the-agent)
1. [Installer Ingress](#install-ingress)
1. [Configurer Auto DevOps](#configure-auto-devops)
1. [Activer Auto DevOps et exécuter le pipeline](#enable-auto-devops-and-run-the-pipeline)
1. [Déployer l'application](#deploy-the-application)

## Configurer votre compte Google {#configure-your-google-account}

Avant de créer votre cluster Kubernetes et de le connecter à votre projet GitLab, vous devez disposer d'un [compte Google Cloud Platform](https://console.cloud.google.com). Connectez-vous avec un compte Google existant, comme celui que vous utilisez pour accéder à Gmail ou Google Drive, ou créez-en un nouveau.

1. Suivez les étapes décrites dans la [section « Avant de commencer »](https://cloud.google.com/kubernetes-engine/docs/deploy-app-cluster#before-you-begin) de la documentation de Kubernetes Engine pour activer les API requises et les services associés.
1. Assurez-vous d'avoir créé un [compte de facturation](https://cloud.google.com/billing/docs/how-to/manage-billing-account) avec Google Cloud Platform.

> [!note]
> Chaque nouveau compte Google Cloud Platform (GCP) reçoit [300 $ de crédit](https://console.cloud.google.com/freetrial), et en partenariat avec Google, GitLab est en mesure d'offrir 200 $ supplémentaires aux nouveaux comptes GCP pour démarrer avec l'intégration GitLab et Google Kubernetes Engine. [Suivez ce lien](https://cloud.google.com/partners?pcn_code=0014M00001h35gDQAQ#contact-form) et faites une demande de crédit.

## Créer un cluster Kubernetes {#create-a-kubernetes-cluster}

Pour créer un nouveau cluster sur Google Kubernetes Engine (GKE), utilisez l'approche Infrastructure as Code (IaC) en suivant les étapes du guide [Créer un cluster Google GKE avec OpenTofu et GitLab](../../../user/infrastructure/iac/_index.md). Le guide vous demande de créer un nouveau projet qui utilise [Terraform](https://developer.hashicorp.com/terraform) pour créer un cluster GKE et installer un agent GitLab pour Kubernetes. Ce projet contient la configuration de l'agent GitLab pour Kubernetes.

## Créer un projet d'application à partir d'un modèle {#create-an-application-project-from-a-template}

Utilisez un modèle de projet GitLab pour démarrer. Comme leur nom l'indique, ces projets fournissent une application de base construite sur des frameworks bien connus.

> [!warning]
> Créez le projet d'application dans la hiérarchie de groupes au même niveau ou en dessous du projet de gestion du cluster. Dans le cas contraire, l'[autorisation de l'agent](../../../user/clusters/agent/ci_cd_workflow.md#authorize-agent-access) échoue.

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) et **Nouveau projet/dépôt**.
1. Sélectionnez **Créer à partir d'un modèle**.
1. Sélectionnez le modèle **Ruby on Rails**.
1. Donnez un nom à votre projet, éventuellement une description, et rendez-le public afin de pouvoir bénéficier des fonctionnalités disponibles dans le [forfait GitLab Ultimate](https://about.gitlab.com/pricing/).
1. Sélectionnez **Créer le projet**.

Vous disposez maintenant d'un projet d'application que vous allez déployer sur le cluster GKE.

## Configurer l'agent {#configure-the-agent}

Configurez maintenant l'agent GitLab pour Kubernetes afin de pouvoir l'utiliser pour déployer le projet d'application.

1. Accédez au projet [que vous avez créé pour gérer le cluster](#create-a-kubernetes-cluster).
1. Accédez au [fichier de configuration de l'agent](../../../user/clusters/agent/install/_index.md#create-an-agent-configuration-file) (`.gitlab/agents/<agent-name>/config.yaml`) et modifiez-le.
1. Configurez l'attribut `ci_access:projects`. Utilisez le chemin du projet de l'application comme `id` :

```yaml
ci_access:
  projects:
    - id: path/to/application-project
```

## Installer Ingress {#install-ingress}

Une fois votre cluster opérationnel, vous devez installer le contrôleur NGINX Ingress en tant qu'équilibreur de charge, afin d'acheminer le trafic d'Internet vers votre application. Installez le contrôleur NGINX Ingress via le [modèle de projet de gestion de cluster](../../../user/clusters/management_project_template.md) GitLab, ou manuellement avec Google Cloud Shell :

1. Accédez à la page de détails de votre cluster et sélectionnez l'onglet **Paramètres avancés**.
1. Sélectionnez le lien vers Google Kubernetes Engine pour accéder au cluster dans Google Cloud Console.
1. Sur la page du cluster GKE, sélectionnez **Connecter**, puis sélectionnez **Exécuter dans Cloud Shell**.
1. Une fois Cloud Shell démarré, exécutez ces commandes pour installer le contrôleur NGINX Ingress :

   ```shell
   helm upgrade --install ingress-nginx ingress-nginx \
   --repo https://kubernetes.github.io/ingress-nginx \
   --namespace gitlab-managed-apps --create-namespace

   # Check that the ingress controller is installed successfully
   kubectl get service ingress-nginx-controller -n gitlab-managed-apps
   ```

## Configurer Auto DevOps {#configure-auto-devops}

Suivez ces étapes pour configurer le domaine de base et les autres paramètres requis pour Auto DevOps.

1. Quelques minutes après l'installation de NGINX, l'équilibreur de charge obtient une adresse IP, et vous pouvez récupérer l'adresse IP externe avec la commande suivante :

   ```shell
   kubectl get service ingress-nginx-controller -n gitlab-managed-apps -ojson | jq -r '.status.loadBalancer.ingress[].ip'
   ```

   Remplacez `gitlab-managed-apps` si vous avez remplacé votre espace de nommage.

   Copiez cette adresse IP, car vous en aurez besoin à l'étape suivante.
1. Revenez au projet d'application.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD** et développez **Variables**.
   - Ajoutez une clé appelée `KUBE_INGRESS_BASE_DOMAIN` avec le domaine de déploiement de l'application comme valeur. Pour cet exemple, utilisez le domaine `<IP address>.nip.io`.
   - Ajoutez une clé appelée `KUBE_NAMESPACE` avec comme valeur l'espace de nommage Kubernetes ciblé par vos déploiements. Vous pouvez utiliser des espaces de nommage différents par environnement. Configurez l'environnement et utilisez la portée d'environnement.
   - Ajoutez une clé appelée `KUBE_CONTEXT` avec la valeur `<path/to/agent/project>:<agent-name>`. Sélectionnez la portée d'environnement de votre choix.
   - Sélectionnez **Enregistrer les modifications**.

## Activer Auto DevOps et exécuter le pipeline {#enable-auto-devops-and-run-the-pipeline}

Bien qu'Auto DevOps soit activé par défaut, il peut être désactivé à la fois pour l'instance (pour les instances GitLab Self-Managed) et pour le groupe. Suivez ces étapes pour activer Auto DevOps s'il est désactivé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet d'application.
1. Sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Auto DevOps**.
1. Sélectionnez **Pipeline Auto DevOps par défaut** pour afficher plus d'options.
1. Dans **Stratégie de déploiement**, sélectionnez la [stratégie de déploiement continu](../requirements.md#auto-devops-deployment-strategy) souhaitée pour déployer l'application en production une fois que le pipeline s'est exécuté avec succès sur la branche par défaut.
1. Sélectionnez **Enregistrer les modifications**.
1. Modifiez le fichier `.gitlab-ci.yml` pour inclure le modèle Auto DevOps et validez la modification sur la branche `master` :

   ```yaml
   include:
   - template: Auto-DevOps.gitlab-ci.yml
   ```

Le commit devrait déclencher un pipeline. La section suivante explique ce que chaque job fait dans le pipeline.

## Déployer l'application {#deploy-the-application}

Que se passe-t-il lors de l'exécution de votre pipeline ?

Pour afficher les jobs du pipeline, sélectionnez le badge de statut du pipeline. L'icône {{< icon name="status_running" >}} s'affiche lorsque les jobs du pipeline sont en cours d'exécution, et se met à jour sans actualiser la page pour afficher {{< icon name="status_success" >}} (en cas de succès) ou {{< icon name="status_failed" >}} (en cas d'échec) une fois les jobs terminés.

Les jobs sont répartis en étapes :

![Étapes du pipeline](img/guide_pipeline_stages_v13_0.png)

- **Version** \- L'application crée une image Docker et la charge dans le [registre de conteneurs](../../../user/packages/container_registry/_index.md) de votre projet ([Auto Build](../stages.md#auto-build)).
- **Test** \- GitLab effectue diverses vérifications sur l'application, mais tous les jobs sauf `test` sont autorisés à échouer dans l'étape de test :

  - Le job `test` exécute des tests unitaires et d'intégration en détectant le langage et le framework ([Auto Test](../stages.md#auto-test))
  - Le job `code_quality` vérifie la qualité du code et est autorisé à échouer ([Auto Code Quality](../stages.md#auto-code-quality))
  - Le job `container_scanning` vérifie si le conteneur Docker présente des vulnérabilités et est autorisé à échouer ([auto container scanning](../stages.md#auto-container-scanning))
  - Le job `dependency_scanning` vérifie si l'application comporte des dépendances susceptibles de présenter des vulnérabilités et est autorisé à échouer ([Analyse automatique des dépendances](../stages.md#auto-dependency-scanning))
  - Les jobs dont le suffixe est `-sast` effectuent une analyse statique du code actuel pour rechercher les problèmes de sécurité potentiels, et sont autorisés à échouer ([Auto SAST](../stages.md#auto-sast))
  - Le job `secret-detection` recherche les secrets exposés et est autorisé à échouer ([détection automatique des secrets](../stages.md#auto-secret-detection))
- **Examen** \- Les pipelines sur la branche par défaut incluent cette étape avec un job `dast_environment_deploy`. Pour plus d'informations, voir [test dynamique de sécurité des applications (DAST)](../../../user/application_security/dast/_index.md).
- **Production** \- Une fois les tests et les vérifications terminés, l'application est déployée dans Kubernetes ([Auto Deploy](../stages.md#auto-deploy)).
- **Performance** \- Des tests de performance sont exécutés sur l'application déployée ([Auto Browser Performance Testing](../stages.md#auto-browser-performance-testing)).
- **Nettoyage** \- Les pipelines sur la branche par défaut incluent cette étape avec un job `stop_dast_environment`.

Après l'exécution d'un pipeline, vous devriez consulter votre site web déployé et apprendre à le surveiller.

### Surveiller votre projet {#monitor-your-project}

Après avoir déployé votre application avec succès, vous pouvez consulter son site web et vérifier son état sur la page **Environnements** en accédant à **Opération** > **Environnements**. Cette page affiche des informations sur les applications déployées, et la colonne de droite affiche des icônes vous donnant accès aux tâches courantes liées aux environnements :

![Environnements](img/guide_environments_v12_3.png)

- **Ouvrir l'environnement en cours** ({{< icon name="external-link" >}}) - Ouvre l'URL de l'application déployée en production
- **Surveillance** ({{< icon name="chart" >}}) - Ouvre la page de métriques où Prometheus collecte des données sur le cluster Kubernetes et l'impact de l'application en termes d'utilisation de la mémoire, d'utilisation du CPU et de latence
- **Déployer vers** ({{< icon name="play" >}} {{< icon name="chevron-lg-down" >}}) - Affiche la liste des environnements sur lesquels vous pouvez déployer
- **Terminal** ({{< icon name="terminal" >}}) - Ouvre une session de [terminal web](../../../ci/environments/_index.md#web-terminals-deprecated) dans le conteneur où l'application est en cours d'exécution
- **Redéployer dans l'environnement** ({{< icon name="repeat" >}}) - Pour plus d'informations, voir [Nouvelle tentative et restauration](../../../ci/environments/deployments.md#retry-or-roll-back-a-deployment)
- **Arrêter l'environnement** ({{< icon name="stop" >}}) - Pour plus d'informations, voir [Arrêt d'un environnement](../../../ci/environments/_index.md#stopping-an-environment)

GitLab affiche le [tableau de déploiement](../../../user/project/deploy_boards.md) sous les informations de l'environnement, avec des carrés représentant les pods de votre cluster Kubernetes, codés par couleur pour indiquer leur statut. Survoler un carré du tableau de déploiement affiche l'état du déploiement, et sélectionner le carré vous amène à la page des journaux du pod.

> [!note]
> L'exemple ne montre qu'un seul pod hébergeant l'application pour le moment, mais vous pouvez en ajouter davantage en définissant la [variable CI/CD `REPLICAS`](../cicd_variables.md) dans **Paramètres** > **CI/CD** > **Variables**.

### Travailler avec les branches {#work-with-branches}

Ensuite, créez une branche de fonctionnalité pour ajouter du contenu à votre application :

1. Dans le dépôt de votre projet, accédez au fichier suivant : `app/views/welcome/index.html.erb`. Ce fichier ne doit contenir qu'un paragraphe : `<p>You're on Rails!</p>`.
1. Ouvrez le [Web IDE](../../../user/project/web_ide/_index.md) GitLab pour effectuer la modification.
1. Modifiez le fichier pour qu'il contienne :

   ```html
   <p>You're on Rails! Powered by GitLab Auto DevOps.</p>
   ```

1. Indexez le fichier. Ajoutez un message de commit, puis créez une nouvelle branche et une merge request en sélectionnant **Commit**.

   ![Commit dans Web IDE](img/guide_ide_commit_v12_3.png)

Après avoir soumis la merge request, GitLab exécute votre pipeline et tous les jobs qu'il contient, comme [décrit précédemment](#deploy-the-application), en plus de quelques jobs supplémentaires qui s'exécutent uniquement sur les branches autres que la branche par défaut.

Au bout de quelques minutes, un test échoue, ce qui signifie qu'un test a été « cassé » par votre modification. Sélectionnez le job `test` en échec pour obtenir plus d'informations :

```plaintext
Failure:
WelcomeControllerTest#test_should_get_index [/app/test/controllers/welcome_controller_test.rb:7]:
<You're on Rails!> expected but was
<You're on Rails! Powered by GitLab Auto DevOps.>..
Expected 0 to be >= 1.

bin/rails test test/controllers/welcome_controller_test.rb:4
```

Pour corriger le test défaillant :

1. Revenez à votre merge request.
1. Dans le coin supérieur droit, sélectionnez **Code**, puis sélectionnez **Ouvrir dans Web EDI**.
1. Dans le répertoire de fichiers de gauche, trouvez le fichier `test/controllers/welcome_controller_test.rb` et sélectionnez-le pour l'ouvrir.
1. Modifiez la ligne 7 pour qu'elle indique `You're on Rails! Powered by GitLab Auto DevOps.`
1. Dans la barre latérale gauche, sélectionnez **Contrôle de source** ({{< icon name="merge" >}}).
1. Rédigez un message de commit et sélectionnez **Commit**.

Revenez à la page **Vue d'ensemble** de votre merge request : vous devriez non seulement voir le test réussi, mais aussi l'application déployée en tant qu'[application de revue](../stages.md#auto-review-apps). Vous pouvez la visiter en sélectionnant le bouton **Voir l'application** {{< icon name="external-link" >}} pour consulter vos modifications déployées.

Après la fusion de la merge request, GitLab exécute le pipeline sur la branche par défaut, puis déploie l'application en production.

## Conclusion {#conclusion}

Après avoir mis en œuvre ce projet, vous devriez avoir une bonne compréhension des bases d'Auto DevOps. Vous êtes passé de la création et des tests au déploiement et à la surveillance d'une application, le tout dans GitLab. Malgré sa nature automatique, Auto DevOps peut également être configuré et personnalisé pour s'adapter à votre workflow. Voici quelques ressources utiles pour aller plus loin :

1. [Fonctionnalité Auto DevOps](../_index.md)
1. [Plusieurs clusters Kubernetes](../multiple_clusters_auto_devops.md)
1. [Déploiement progressif en production](../cicd_variables.md#incremental-rollout-to-production)
1. [Désactiver les jobs dont vous n'avez pas besoin avec des variables CI/CD](../cicd_variables.md)
1. [Utiliser vos propres buildpacks pour créer votre application](../customize.md#custom-buildpacks)
