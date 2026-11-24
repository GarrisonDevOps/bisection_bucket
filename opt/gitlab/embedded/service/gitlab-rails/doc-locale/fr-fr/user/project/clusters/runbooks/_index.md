---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Runbooks
description: "Runbooks exécutables, automatisation, dépannage et opérations."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les runbooks sont un ensemble de procédures documentées qui expliquent comment effectuer un processus particulier, qu'il s'agisse de démarrer, d'arrêter, de déboguer ou de dépanner un système particulier.

En utilisant [Jupyter Notebooks](https://jupyter.org/) et la [bibliothèque Rubix](https://github.com/Nurtch/rubix), les utilisateurs peuvent commencer à écrire leurs propres runbooks exécutables.

Historiquement, les runbooks prenaient la forme d'un arbre de décision ou d'un guide détaillé étape par étape selon la condition ou le système.

Les implémentations modernes ont introduit le concept de « runbook exécutable », dans lequel, en plus d'un processus bien défini, les opérateurs peuvent exécuter des blocs de code pré-écrits ou des requêtes de base de données sur un environnement donné.

## Runbooks exécutables {#executable-runbooks}

L'application JupyterHub proposée avec l'intégration Kubernetes de GitLab intègre désormais la bibliothèque Nurtch Rubix, offrant un moyen simple de créer des runbooks DevOps. Un exemple de runbook est fourni, présentant les opérations courantes. Bien que Rubix simplifie la création de workflows Kubernetes et AWS courants, vous pouvez également les créer manuellement sans Rubix.

<i class="fa-youtube-play" aria-hidden="true"></i> Regardez cette [vidéo](https://www.youtube.com/watch?v=Q_OqHIIUPjE) pour avoir un aperçu de la façon dont cela est accompli dans GitLab !

## Prérequis {#requirements}

Pour créer un runbook exécutable, vous avez besoin des éléments suivants :

- **Kubernetes** \- Un cluster Kubernetes est nécessaire pour déployer le reste des applications. Le moyen le plus simple pour commencer est de connecter un cluster à l'aide de [l'agent GitLab pour Kubernetes](../../../clusters/agent/_index.md).
- **Ingress** \- Ingress peut fournir l'équilibrage de charge, la terminaison SSL et l'hébergement virtuel basé sur le nom. Il fait office de proxy web pour vos applications.
- **JupyterHub** - [JupyterHub](https://jupyterhub.readthedocs.io/en/stable/) est un service multi-utilisateurs permettant de gérer des notebooks au sein d'une équipe. Les Jupyter Notebooks offrent un environnement de programmation interactif basé sur le web, utilisé pour l'analyse de données, la visualisation et l'apprentissage automatique.

## Nurtch {#nurtch}

Nurtch est la société à l'origine de la [bibliothèque Rubix](https://github.com/Nurtch/rubix). Rubix est une bibliothèque Python open source qui facilite l'exécution des tâches DevOps courantes dans les Jupyter Notebooks. Des tâches telles que la représentation graphique des métriques Cloudwatch et la mise à jour de votre application ECS/Kubernetes sont simplifiées en quelques lignes de code. Consultez la [documentation Nurtch](https://docs.nurtch.com/en/latest/) pour plus d'informations.

## Configurer un runbook exécutable avec GitLab {#configure-an-executable-runbook-with-gitlab}

Suivez ce guide étape par étape pour configurer un runbook exécutable dans GitLab en utilisant les composants décrits précédemment et le runbook de démonstration préchargé.

1. Créez une [application OAuth pour JupyterHub](../../../../integration/oauth_provider.md).
1. Lors de l'[installation de JupyterHub avec Helm](https://zero-to-jupyterhub.readthedocs.io/en/latest/jupyterhub/installation.html), utilisez les valeurs suivantes :

   ```yaml
   #-----------------------------------------------------------------------------
   # The hub.config.GitLabOAuthenticator section must be customized!
   #-----------------------------------------------------------------------------

   hub:
     config:
       GitLabOAuthenticator:
         # Limit access to members of specific projects or groups or to specific users:
         # allowedGitlabGroups: [ "my-group-1", "my-group-2" ]
         # allowedProjectIds: [ 12345, 6789 ]
         # allowed_users: ["user-1", "user-2"]
         client_id: <Your OAuth Application ID>
         client_secret: <Your OAuth Application ID>
         enable_auth_state: true
         gitlab_url: https://gitlab.example.com
         oauth_callback_url: http://<Jupyter Hostname>/hub/oauth_callback
         scope:
           - read_user
           - read_api
           - openid
           - profile
           - email
       JupyterHub:
         authenticator_class: gitlab
      extraConfig:
        gitlab-config: |
           c.KubeSpawner.cmd = ['jupyter-labhub']
           c.GitLabOAuthenticator.scope = ['api read_repository write_repository']

           async def add_auth_env(spawner):
              '''
              Set user's id, login and access token on single user image to
              enable repository integration for JupyterHub.
              See: https://gitlab.com/gitlab-org/gitlab-foss/-/issues/47138#note_154294790
              '''
              auth_state = await spawner.user.get_auth_state()

              if not auth_state:
                 spawner.log.warning("No auth state for %s", spawner.user)
                 return

              spawner.environment['GITLAB_ACCESS_TOKEN'] = auth_state['access_token']
              spawner.environment['GITLAB_USER_EMAIL'] = auth_state['gitlab_user']['email']
              spawner.environment['GITLAB_USER_ID'] = str(auth_state['gitlab_user']['id'])
              spawner.environment['GITLAB_USER_LOGIN'] = auth_state['gitlab_user']['username']
              spawner.environment['GITLAB_USER_NAME'] = auth_state['gitlab_user']['name']

           c.KubeSpawner.pre_spawn_hook = add_auth_env

   singleuser:
      defaultUrl: "/lab"
      image:
         name: registry.gitlab.com/gitlab-org/jupyterhub-user-image
         tag: latest
      lifecycleHooks:
         postStart:
            exec:
            command:
               - "sh"
               - "-c"
               - >
                  git clone https://gitlab.com/gitlab-org/nurtch-demo.git DevOps-Runbook-Demo || true;
                  echo "https://oauth2:${GITLAB_ACCESS_TOKEN}@${GITLAB_HOST}" > ~/.git-credentials;
                  git config --global credential.helper store;
                  git config --global user.email "${GITLAB_USER_EMAIL}";
                  git config --global user.name "${GITLAB_USER_NAME}";
                  jupyter serverextension enable --py jupyterlab_git

   proxy:
      service:
         type: ClusterIP
   ```

1. Une fois JupyterHub installé avec succès, ouvrez le **Jupyter Hostname** dans votre navigateur. Sélectionnez le bouton **Sign in with GitLab** pour vous connecter à JupyterHub et démarrer le serveur. L'authentification est activée pour tout utilisateur de l'instance GitLab avec OAuth2. Ce bouton vous redirige vers une page GitLab demandant l'autorisation à JupyterHub d'utiliser votre compte GitLab.

   ![Boîte de dialogue d'autorisation demandant la permission à Jupyter d'accéder à votre compte GitLab.](img/authorize_jupyter_v11_6.png)

1. Sélectionnez **Autoriser**, et GitLab vous redirige vers l'application JupyterHub.
1. Sélectionnez **Start My Server** pour démarrer le serveur en quelques secondes.
1. Pour configurer l'accès du runbook à votre projet GitLab, vous devez saisir votre [jeton d'accès GitLab](../../../profile/personal_access_tokens.md) et votre ID de projet dans la section **Configuration** du runbook de démonstration :

   1. Sélectionnez le dossier **DevOps-Runbook-Demo** situé dans le panneau de gauche.

      ![Lanceur JupyterHub affichant le dossier DevOps-Runbook-Demo dans le navigateur de fichiers.](img/demo_runbook_v11_6.png)

   1. Sélectionnez le runbook `Nurtch-DevOps-Demo.ipynb`.

      ![Navigateur de fichiers JupyterHub avec le runbook Nurtch-DevOps-Demo.ipynb sélectionné.](img/sample_runbook_v11_6.png)

      Jupyter affiche le contenu du runbook sur le côté droit de l'écran. La section **Configuration** affiche votre `PRIVATE_TOKEN` et votre `PROJECT_ID`. Saisissez ces valeurs en conservant les guillemets simples comme suit :

      ```sql
      PRIVATE_TOKEN = '<your_access_token>'
      PROJECT_ID = '1234567'
      ```

   1. Mettez à jour le `VARIABLE_NAME` sur la dernière ligne de cette section pour qu'il corresponde au nom de la variable que vous utilisez pour votre jeton d'accès. Dans cet exemple, notre nom de variable est `PRIVATE_TOKEN`.

      ```sql
      VARIABLE_VALUE = project.variables.get('PRIVATE_TOKEN').value
      ```

1. Pour configurer le fonctionnement d'un runbook, créez et configurez des variables CI/CD. Cet exemple utilise la section **Run SQL queries in Notebook** du runbook d'exemple pour interroger une base de données PostgreSQL. Les quatre premières lignes du bloc de code suivant définissent les variables CI/CD nécessaires au fonctionnement de cette requête :

   ```sql
   %env DB_USER={project.variables.get('DB_USER').value}
   %env DB_PASSWORD={project.variables.get('DB_PASSWORD').value}
   %env DB_ENDPOINT={project.variables.get('DB_ENDPOINT').value}
   %env DB_NAME={project.variables.get('DB_NAME').value}
   ```

   1. Accédez à **Paramètres** > **CI/CD** > **Variables** pour créer les variables CI/CD dans votre projet.

      ![Variables de base de données ajoutées dans la page des variables CI/CD d'un projet avec des valeurs masquées.](img/gitlab_variables_v11_6.png)

   1. Sélectionnez **Save variables**.

   1. Dans Jupyter, sélectionnez l'en-tête **Run SQL queries in Notebook**, puis sélectionnez **Exécution**. Les résultats s'affichent en ligne comme suit :

      ![Jupyter Notebook exécutant une requête PostgreSQL avec des variables de base de données et affichant les résultats.](img/postgres_query_v11_6.png)

Vous pouvez essayer d'autres opérations, telles que l'exécution de scripts shell ou l'interaction avec un cluster Kubernetes. Consultez la [documentation Nurtch](https://docs.nurtch.com/en/latest/) pour plus d'informations.
