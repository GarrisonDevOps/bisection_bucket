---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Utiliser Auto DevOps pour déployer une application sur Amazon Elastic Kubernetes Service (EKS)
---

Ce tutoriel vous explique comment démarrer avec [Auto DevOps](../_index.md) à travers un exemple de déploiement d'une application sur Amazon Elastic Kubernetes Service (EKS).

Ce tutoriel utilise l'intégration Kubernetes native de GitLab, ce qui vous évite de créer manuellement un cluster Kubernetes via la console AWS.

Vous pouvez également suivre ce tutoriel sur une instance GitLab Self-Managed. Assurez-vous que vos propres [runners sont configurés](../../../ci/runners/_index.md).

Pour déployer un projet sur EKS :

1. [Configurer votre compte Amazon](#configure-your-amazon-account)
1. [Créer un cluster Kubernetes et déployer l'agent](#create-a-kubernetes-cluster)
1. [Créer un nouveau projet à partir d'un modèle](#create-an-application-project-from-a-template)
1. [Configurer l'agent](#configure-the-agent)
1. [Installer Ingress](#install-ingress)
1. [Configurer Auto DevOps](#configure-auto-devops)
1. [Activer Auto DevOps et exécuter le pipeline](#enable-auto-devops-and-run-the-pipeline)
1. [Déployer l'application](#deploy-the-application)

## Configurer votre compte Amazon {#configure-your-amazon-account}

Avant de créer et de connecter votre cluster Kubernetes à votre projet GitLab, vous avez besoin d'un [compte Amazon Web Services](https://aws.amazon.com/). Connectez-vous avec un compte Amazon existant ou créez-en un nouveau.

## Créer un cluster Kubernetes {#create-a-kubernetes-cluster}

Pour créer un nouveau cluster sur Amazon EKS :

- Suivez les étapes décrites dans [Créer un cluster Amazon EKS](../../../user/infrastructure/clusters/connect/new_eks_cluster.md).

Si vous préférez, vous pouvez également créer un cluster manuellement à l'aide de `eksctl`.

## Créer un projet d'application à partir d'un modèle {#create-an-application-project-from-a-template}

Utilisez un modèle de projet GitLab pour démarrer. Comme leur nom l'indique, ces projets fournissent une application minimaliste construite sur des frameworks reconnus.

> [!warning]
> Créez le projet d'application dans la hiérarchie de groupes au même niveau que le projet de gestion du cluster ou en dessous. Dans le cas contraire, il ne parvient pas à [autoriser l'agent](../../../user/clusters/agent/ci_cd_workflow.md#authorize-agent-access).

1. Dans le coin supérieur droit, sélectionnez **Créer un nouveau** ({{< icon name="plus" >}}) puis **Nouveau projet/dépôt**.
1. Sélectionnez **Créer à partir d'un modèle**.
1. Sélectionnez le modèle **Ruby on Rails**.
1. Donnez un nom à votre projet, éventuellement une description, et rendez-le public afin de bénéficier des fonctionnalités disponibles dans le [plan GitLab Ultimate](https://about.gitlab.com/pricing/).
1. Sélectionnez **Créer le projet**.

Vous disposez maintenant d'un projet d'application à déployer sur le cluster EKS.

## Configurer l'agent {#configure-the-agent}

Ensuite, configurez l'agent GitLab pour Kubernetes afin de pouvoir l'utiliser pour déployer le projet d'application.

1. Accédez au projet [que vous avez créé pour gérer le cluster](#create-a-kubernetes-cluster).
1. Accédez au [fichier de configuration de l'agent](../../../user/clusters/agent/install/_index.md#create-an-agent-configuration-file) (`.gitlab/agents/eks-agent/config.yaml`) et modifiez-le.
1. Configurez l'attribut `ci_access:projects`. Utilisez le chemin du projet d'application comme `id` :

```yaml
ci_access:
  projects:
    - id: path/to/application-project
```

## Installer Ingress {#install-ingress}

Une fois votre cluster en cours d'exécution, vous devez installer NGINX Ingress Controller comme équilibreur de charge pour acheminer le trafic en provenance d'Internet vers votre application. Installez NGINX Ingress Controller via le [modèle de projet de gestion de cluster](../../../user/clusters/management_project_template.md) GitLab, ou manuellement en ligne de commande :

1. Assurez-vous que `kubectl` et Helm sont installés sur votre machine.
1. Créez un rôle IAM pour accéder au cluster.
1. Créez un jeton d'accès pour accéder au cluster.
1. Utilisez `kubectl` pour vous connecter à votre cluster :

   ```shell
   helm upgrade --install ingress-nginx ingress-nginx \
   --repo https://kubernetes.github.io/ingress-nginx \
   --namespace gitlab-managed-apps --create-namespace

   # Check that the ingress controller is installed successfully
   kubectl get service ingress-nginx-controller -n gitlab-managed-apps
   ```

## Configurer Auto DevOps {#configure-auto-devops}

Suivez ces étapes pour configurer le domaine de base et les autres paramètres requis pour Auto DevOps.

1. Quelques minutes après l'installation de NGINX, l'équilibreur de charge obtient une adresse IP, et vous pouvez récupérer l'adresse IP externe à l'aide de la commande suivante :

   ```shell
   kubectl get all -n gitlab-managed-apps --selector app.kubernetes.io/instance=ingress-nginx
   ```

   Remplacez `gitlab-managed-apps` si vous avez remplacé votre espace de nommage.

   Ensuite, trouvez l'adresse IP externe réelle de votre cluster à l'aide de la commande suivante :

   ```shell
   nslookup [External IP]
   ```

   Où `[External IP]` est le nom d'hôte trouvé avec la commande précédente.

   L'adresse IP peut être répertoriée dans la section `Non-authoritative answer:` de la réponse.

   Copiez cette adresse IP, car vous en aurez besoin à l'étape suivante.
1. Revenez au projet d'application.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD** et développez **Variables**.
   - Ajoutez une clé appelée `KUBE_INGRESS_BASE_DOMAIN` avec le domaine de déploiement de l'application comme valeur. Pour cet exemple, utilisez le domaine `<IP address>.nip.io`.
   - Ajoutez une clé appelée `KUBE_NAMESPACE` avec comme valeur l'espace de nommage Kubernetes ciblé par vos déploiements. Vous pouvez utiliser différents espaces de nommage par environnement. Configurez l'environnement, utilisez la portée de l'environnement.
   - Ajoutez une clé appelée `KUBE_CONTEXT` avec une valeur telle que `path/to/agent/project:eks-agent`. Sélectionnez la portée d'environnement de votre choix.
   - Sélectionnez **Enregistrer les modifications**.

## Activer Auto DevOps et exécuter le pipeline {#enable-auto-devops-and-run-the-pipeline}

Bien qu'Auto DevOps soit activé par défaut, il peut être désactivé pour l'ensemble de l'instance (pour les instances GitLab Self-Managed) ainsi que pour des groupes individuels. Effectuez ces étapes pour activer Auto DevOps s'il est désactivé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez le projet d'application.
1. Sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Auto DevOps**.
1. Sélectionnez **Pipeline Auto DevOps par défaut** pour afficher plus d'options.
1. Dans **Stratégie de déploiement**, sélectionnez la [stratégie de déploiement continu](../requirements.md#auto-devops-deployment-strategy) souhaitée pour déployer l'application en production après l'exécution réussie du pipeline sur la branche par défaut.
1. Sélectionnez **Enregistrer les modifications**.
1. Modifiez le fichier `.gitlab-ci.yml` pour y inclure le modèle Auto DevOps et validez la modification sur la branche par défaut :

   ```yaml
   include:
   - template: Auto-DevOps.gitlab-ci.yml
   ```

Le commit doit déclencher un pipeline. La section suivante explique ce que chaque job effectue dans le pipeline.

## Déployer l'application {#deploy-the-application}

Que se passe-t-il lorsque votre pipeline s'exécute ?

Pour afficher les jobs dans le pipeline, sélectionnez le badge de statut du pipeline. L'icône {{< icon name="status_running" >}} s'affiche lorsque les jobs du pipeline sont en cours d'exécution, et se met à jour sans actualiser la page en {{< icon name="status_success" >}} (en cas de succès) ou {{< icon name="status_failed" >}} (en cas d'échec) lorsque les jobs se terminent.

Les jobs sont répartis en étapes :

![Étapes du pipeline](img/guide_pipeline_stages_v13_0.png)

- **Version** \- L'application génère une image Docker et la charge dans le [registre de conteneurs](../../../user/packages/container_registry/_index.md) de votre projet ([Auto Build](../stages.md#auto-build)).
- **Test** \- GitLab effectue diverses vérifications sur l'application, mais tous les jobs à l'exception de `test` sont autorisés à échouer dans l'étape de test :

  - Le job `test` exécute des tests unitaires et d'intégration en détectant le langage et le framework ([Auto Test](../stages.md#auto-test))
  - Le job `code_quality` vérifie la qualité du code et est autorisé à échouer ([Auto Code Quality](../stages.md#auto-code-quality))
  - Le job `container_scanning` vérifie si le conteneur Docker présente des vulnérabilités et est autorisé à échouer ([auto container scanning](../stages.md#auto-container-scanning))
  - Le job `dependency_scanning` vérifie si l'application possède des dépendances susceptibles de présenter des vulnérabilités et est autorisé à échouer ([Analyse automatique des dépendances](../stages.md#auto-dependency-scanning))
  - Les jobs dont le suffixe est `-sast` effectuent une analyse statique du code actuel pour détecter d'éventuels problèmes de sécurité, et sont autorisés à échouer ([Auto SAST](../stages.md#auto-sast))
  - Le job `secret-detection` vérifie la présence de secrets exposés et est autorisé à échouer ([détection automatique des secrets](../stages.md#auto-secret-detection))
- **Examen** \- Les pipelines sur la branche par défaut incluent cette étape avec un job `dast_environment_deploy`. Pour en savoir plus, consultez [le test dynamique de sécurité des applications (DAST)](../../../user/application_security/dast/_index.md).
- **Production** \- Une fois les tests et vérifications terminés, l'application est déployée dans Kubernetes ([Auto Deploy](../stages.md#auto-deploy)).
- **Performance** \- Des tests de performance sont exécutés sur l'application déployée ([Auto Browser Performance Testing](../stages.md#auto-browser-performance-testing)).
- **Nettoyage** \- Les pipelines sur la branche par défaut incluent cette étape avec un job `stop_dast_environment`.

Après l'exécution d'un pipeline, vous devriez consulter votre site web déployé et apprendre à le surveiller.

### Surveiller votre projet {#monitor-your-project}

Après avoir déployé votre application avec succès, vous pouvez consulter son site web et vérifier son état sur la page **Environnements** en accédant à **Opération** > **Environnements**. Cette page affiche des informations sur les applications déployées, et la colonne de droite affiche des icônes qui vous donnent accès aux tâches courantes liées à l'environnement :

![Environnements](img/guide_environments_v12_3.png)

- **Ouvrir l'environnement en cours** ({{< icon name="external-link" >}}) - Ouvre l'URL de l'application déployée en production
- **Surveillance** ({{< icon name="chart" >}}) - Ouvre la page des métriques où Prometheus collecte des données sur le cluster Kubernetes et sur l'impact de l'application en termes d'utilisation de la mémoire, d'utilisation du CPU et de latence
- **Déployer vers** ({{< icon name="play" >}} {{< icon name="chevron-lg-down" >}}) - Affiche la liste des environnements vers lesquels vous pouvez déployer
- **Terminal** ({{< icon name="terminal" >}}) - Ouvre une session de [terminal web](../../../ci/environments/_index.md#web-terminals-deprecated) à l'intérieur du conteneur où l'application est en cours d'exécution
- **Redéployer dans l'environnement** ({{< icon name="repeat" >}}) - Pour plus d'informations, consultez [Nouvelle tentative et retour arrière](../../../ci/environments/deployments.md#retry-or-roll-back-a-deployment)
- **Arrêter l'environnement** ({{< icon name="stop" >}}) - Pour plus d'informations, consultez [Arrêt d'un environnement](../../../ci/environments/_index.md#stopping-an-environment)

GitLab affiche le [tableau de déploiement](../../../user/project/deploy_boards.md) sous les informations de l'environnement, avec des carrés représentant les pods de votre cluster Kubernetes, codés par couleur pour indiquer leur statut. Le survol d'un carré sur le tableau de déploiement affiche l'état du déploiement, et la sélection du carré vous amène à la page des journaux du pod.

Bien que l'exemple ne montre qu'un seul pod hébergeant l'application pour le moment, vous pouvez ajouter davantage de pods en définissant la [variable CI/CD `REPLICAS`](../cicd_variables.md) dans **Paramètres** > **CI/CD** > **Variables**.

### Travailler avec les branches {#work-with-branches}

Ensuite, créez une branche de fonctionnalité pour ajouter du contenu à votre application :

1. Dans le dépôt de votre projet, accédez au fichier suivant : `app/views/welcome/index.html.erb`. Ce fichier ne doit contenir qu'un seul paragraphe : `<p>You're on Rails!</p>`.
1. Ouvrez le [Web IDE](../../../user/project/web_ide/_index.md) de GitLab pour effectuer la modification.
1. Modifiez le fichier pour qu'il contienne :

   ```html
   <p>You're on Rails! Powered by GitLab Auto DevOps.</p>
   ```

1. Indexez le fichier. Ajoutez un message de commit, puis créez une nouvelle branche et une merge request en sélectionnant **Commit**.

   ![Commit Web IDE](img/guide_ide_commit_v12_3.png)

Après avoir soumis la merge request, GitLab exécute votre pipeline ainsi que tous les jobs qu'il contient, comme [décrit précédemment](#deploy-the-application), en plus de quelques autres qui s'exécutent uniquement sur les branches autres que la branche par défaut.

Après quelques minutes, un test échoue, ce qui signifie qu'un test a été « cassé » par votre modification. Sélectionnez le job `test` en échec pour obtenir plus d'informations à son sujet :

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
1. Dans le coin supérieur droit, sélectionnez **Code**, puis sélectionnez **Ouvrir dans Web IDE**.
1. Dans le répertoire de fichiers à gauche, trouvez le fichier `test/controllers/welcome_controller_test.rb` et sélectionnez-le pour l'ouvrir.
1. Modifiez la ligne 7 pour indiquer `You're on Rails! Powered by GitLab Auto DevOps.`
1. Dans la barre latérale gauche, sélectionnez **Contrôle de source** ({{< icon name="merge" >}}).
1. Rédigez un message de commit, puis sélectionnez **Commit**.

Revenez à la page **Vue d'ensemble** de votre merge request. Vous devriez non seulement voir le test réussi, mais également l'application déployée en tant qu'[application de revue](../stages.md#auto-review-apps). Vous pouvez la consulter en sélectionnant le bouton **Voir l'application** {{< icon name="external-link" >}} pour voir vos modifications déployées.

Après la fusion de la merge request, GitLab exécute le pipeline sur la branche par défaut, puis déploie l'application en production.

## Conclusion {#conclusion}

Après avoir mis en œuvre ce projet, vous devriez avoir une bonne compréhension des bases d'Auto DevOps. Vous êtes parti de la génération et des tests, jusqu'au déploiement et à la surveillance d'une application, le tout dans GitLab. Malgré son caractère automatique, Auto DevOps peut également être configuré et personnalisé pour s'adapter à votre workflow. Voici quelques ressources utiles pour approfondir le sujet :

1. [Fonctionnalité Auto DevOps](../_index.md)
1. [Plusieurs clusters Kubernetes](../multiple_clusters_auto_devops.md)
1. [Déploiement progressif en production](../cicd_variables.md#incremental-rollout-to-production)
1. [Désactiver les jobs dont vous n'avez pas besoin avec des variables CI/CD](../cicd_variables.md)
1. [Utiliser vos propres buildpacks pour générer votre application](../customize.md#custom-buildpacks)
