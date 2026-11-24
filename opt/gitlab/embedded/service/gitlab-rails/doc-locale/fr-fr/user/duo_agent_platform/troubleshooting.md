---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Résoudre les problèmes courants liés à la plateforme GitLab Duo Agent, notamment les flows, les permissions et la configuration des règles de poussée."
title: Dépannage de la plateforme GitLab Duo Agent
---

Si vous travaillez avec la plateforme GitLab Duo Agent, vous pourriez rencontrer les problèmes suivants.

## Afficher les journaux {#view-logs}

Une fois qu'un flow est créé, vous pouvez afficher sa session en accédant à **IA** > **Sessions**.

L'onglet **Détails** affiche un lien vers les job logs CI/CD. Ces journaux peuvent contenir des informations de dépannage.

## Flows non visibles dans l'interface utilisateur {#flows-not-visible-in-the-ui}

Si vous essayez d'exécuter un flow mais qu'il n'est pas visible dans l'interface GitLab :

1. Assurez-vous d'avoir au minimum le rôle Développeur dans le projet.
1. Assurez-vous que GitLab Duo est [activé et que les flows sont autorisés à s'exécuter](../gitlab_duo/turn_on_off.md).
1. Assurez-vous que le groupe auquel vous appartenez dispose de l'autorisation [d'utiliser les flows](../../administration/gitlab_duo/configure/access_control.md).
1. Si le groupe principal est correctement configuré mais que les flows ne sont pas visibles pour un projet individuel :
   1. Accédez au projet.
   1. Sélectionnez **IA** > **Flows**.
   1. Dans le coin supérieur droit, sélectionnez **Activer le flow à partir du groupe**.
   1. Sélectionnez un flow, puis sélectionnez **Activer**.

1. Si le problème persiste :
   1. Désactivez le flow concerné dans le groupe principal et enregistrez la configuration.
   1. Activez le flow concerné dans le groupe principal et enregistrez la configuration.
   1. Attendez quelques minutes que le paramètre se propage dans vos groupes.

## Autorisations insuffisantes pour créer un nouveau pipeline pour des projets importés {#insufficient-permissions-to-create-a-new-pipeline-for-imported-projects}

Si vous essayez d'exécuter des flows par défaut dans un projet importé ou un projet créé depuis un modèle, vous pourriez obtenir l'erreur : `Error in creating workload: Insufficient permissions to create a new pipeline`.

Pour résoudre ce problème :

1. Accédez au groupe principal.
1. Sélectionnez **Paramètres** > **Généralités**.
1. Développez **Fonctionnalités de GitLab Duo**.
1. Sous **Exécution des flux**, identifiez les flows par défaut que vous souhaitez activer.
1. Désactivez les flows dans le groupe principal et enregistrez la configuration.
1. Activez les mêmes flows dans le groupe principal et enregistrez la configuration.
1. Attendez quelques minutes que le paramètre se propage dans les projets du groupe.

## Erreur : `Your request was valid but Workflow failed to complete it` {#error-your-request-was-valid-but-workflow-failed-to-complete-it}

Les flows nécessitent que le dépôt du projet contienne au moins un commit. Si vous exécutez un flow dans un projet sans commit, vous obtenez l'erreur : `Your request was valid but Workflow failed to complete it. Please try again.`

Cette erreur survient car le flow ne peut pas trouver la branche par défaut dans un dépôt sans commit.

Pour résoudre ce problème, poussez un commit initial vers le projet avant d'exécuter un flow. Par exemple, ajoutez un fichier `README.md`.

## La session est bloquée à l'état créé {#session-is-stuck-in-created-state}

Si une session pour votre flow ne démarre pas :

- Assurez-vous que les règles de poussée sont configurées.

### Configurer les règles de poussée pour autoriser un compte de service {#configure-push-rules-to-allow-a-service-account}

Dans l'interface GitLab, les flows par défaut utilisent un compte de service qui :

- Crée des commits avec sa propre adresse e-mail.
- Crée un [pipeline de workload](../../ci/pipelines/pipeline_types.md#workload-pipeline).

Prérequis :

- Disposer d'un accès administrateur.

Pour configurer les règles de poussée pour un projet :

1. Trouvez l'adresse e-mail associée au compte de service :
   1. Dans le coin supérieur droit, sélectionnez **Admin**.
   1. Sélectionnez **Vue d'ensemble** > **Utilisateurs** et recherchez le compte associé au flow. Le compte suit le modèle `duo-[flow-name]-[top-level-group-name]`.
   1. Localisez l'utilisateur du compte de service et copiez l'adresse e-mail.

1. Autorisez l'adresse e-mail à pousser vers le projet :
   1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
   1. Sélectionnez **Paramètres** > **Dépôt**.
   1. Développez **Règles de poussée**.
   1. Dans **Adresse de courriel de l'auteur de la validation**, ajoutez une expression régulière qui autorise l'adresse e-mail que vous venez de copier.
   1. Sélectionnez **Enregistrer les règles de poussée**.

1. Autorisez le préfixe de branche `duo/feature/` :
   1. Dans la section **Règles de poussée**, trouvez **Nom de la branche**.
   1. Ajoutez une expression régulière qui autorise les branches commençant par ^duo/(fix\|feature\|refactor\|docs/).\* Par exemple : `^(duo/feature)/.*$`
   1. Sélectionnez **Enregistrer les règles de poussée**.

Pour créer des règles de poussée pour l'instance :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Règles de poussée**.
1. Suivez les étapes précédentes pour autoriser **Adresse de courriel de l'auteur de la validation** et **Nom de la branche**.
1. Sélectionnez **Enregistrer les règles de poussée**.

## Le job ou la session d'un flow ne démarre pas {#a-flows-job-or-session-fails-to-start}

Si un job pour un flow ne démarre jamais, ou si le job est bloqué à `Starting job`, aucun runner n'est disponible pour prendre en charge le job. Sur la page de session (**IA** > **Sessions**), l'alerte `Session failed to start` s'affiche.

Les flows s'exécutent sur des runners qui répondent aux exigences suivantes :

- Le runner possède le tag `gitlab--duo`.
- Le runner utilise un exécuteur qui prend en charge les images Docker, comme `docker`, `docker-autoscaler` ou `kubernetes`. L'exécuteur `shell` n'est pas pris en charge.
- Le runner est un runner d'instance ou un runner de groupe assigné au groupe principal. Les runners dont la portée est limitée à un sous-groupe ou à un projet ne prennent pas en charge les jobs de flow, sauf si le feature flag `duo_runner_restrictions` est désactivé.

Pour résoudre ce problème :

1. Sur GitLab.com, confirmez que les [runners hébergés](../../ci/runners/hosted_runners/_index.md) sont activés pour le projet. Les runners hébergés répondent à toutes les exigences par défaut.
1. Si vous utilisez vos propres runners, confirmez qu'au moins un runner répond aux exigences :
   1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre projet ou groupe principal.
   1. Dans la barre latérale gauche, sélectionnez **Version** > **Runners**.
   1. Confirmez qu'un runner avec le tag `gitlab--duo` est en ligne.
1. Facultatif. [Vérifiez la configuration du runner](flows/execution/_index.md#verify-the-runner-configuration) depuis les paramètres du projet, ce qui vérifie le tag, l'exécuteur et la portée ensemble.
1. Si aucun runner ne répond aux exigences, [configurez un runner pour exécuter les flows](flows/execution/_index.md#configure-runners-to-execute-flows).

Si un runner répond à toutes les exigences mais que les jobs ne démarrent toujours pas, vérifiez les points suivants :

- L'espace de nommage a utilisé la totalité de ses [minutes de calcul](../../ci/pipelines/instance_runner_compute_minutes.md#enforcement), ce qui supprime également l'accès aux runners hébergés. Un quota épuisé peut donc ressembler à un problème de disponibilité des runners.
- Le groupe principal [restreint l'accès par adresse IP](../group/access_and_permissions.md#restrict-group-access-by-ip-address). Les runners hébergés utilisent des adresses IP dynamiques qui ne peuvent pas être ajoutées à une liste d'autorisation, et ne peuvent donc pas exécuter des flows pour ce groupe. À la place, configurez votre propre runner au niveau du groupe principal.

## Erreur : `Something went wrong while requesting a review from GitLab Duo` {#error-something-went-wrong-while-requesting-a-review-from-gitlab-duo}

Dans GitLab 18.8 et les versions antérieures, ce message d'erreur apparaît pour les échecs du flow Code Review. Les causes racines les plus courantes sont les suivantes :

- Le compte de service du flow par défaut n'a pas été créé.
- Le verrouillage des membres du groupe empêche l'ajout du compte de service aux projets.
- Vous appartenez à plusieurs espaces de nommage GitLab Duo et aucun espace de nommage par défaut n'est défini.

Dans GitLab 18.9 et les versions ultérieures, des messages d'erreur plus spécifiques s'affichent à la place. Pour plus d'informations, consultez [le dépannage du flow Code Review](flows/foundational_flows/code_review/troubleshooting.md).

### Compte de service du flow par défaut non créé {#foundational-flow-service-account-not-created}

Si un flow par défaut est activé mais ne fonctionne pas, le compte de service pour le groupe principal n'a peut-être pas été créé avec succès.

Pour vérifier si le compte de service existe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Comptes de service**.
1. Recherchez un compte nommé `duo-[flow-name]-[top-level-group-name]`.

Si le compte est manquant, `CascadeSyncFoundationalFlowsWorker` a peut-être échoué lors de sa création. Pour vérifier que le compte est manquant, consultez les journaux Sidekiq pour l'erreur suivante :

```json
{
  "severity": "ERROR",
  "meta.caller_id": "Ai::Catalog::Flows::CascadeSyncFoundationalFlowsWorker",
  "message": "Cannot obtain an exclusive lease. There must be another instance already in execution.",
  "lease_key": "sidekiq:concurrency_limit:{ai/catalog/flows/cascade_sync_foundational_flows_worker}",
  "lease_timeout": 600
}
```

Pour résoudre ce problème, [désactivez les flows par défaut](flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off) et réactivez-les après 10 minutes.

### Membres du groupe verrouillés {#group-membership-locked}

Si [les membres sont verrouillés](../group/access_and_permissions.md#prevent-members-from-being-added-to-projects-in-a-group) pour le groupe principal, les flows par défaut échouent silencieusement car le compte de service ne peut pas être ajouté aux projets requis.

Pour résoudre ce problème :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Permissions et fonctionnalités du groupe**.
1. Décochez la case **Les utilisateurs ne peuvent pas être ajoutés aux projets de ce groupe**, puis sélectionnez **Enregistrer les modifications**.
1. [Désactivez les flows par défaut](flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off), puis sélectionnez **Enregistrer les modifications**.
1. Réactivez les flows par défaut, puis sélectionnez **Enregistrer les modifications**.
1. Cochez la case **Les utilisateurs ne peuvent pas être ajoutés aux projets de ce groupe**, puis sélectionnez **Enregistrer les modifications**.

### Espace de nommage GitLab Duo par défaut non défini {#default-gitlab-duo-namespace-not-set}

Dans GitLab 18.3 et les versions ultérieures, lorsque vous appartenez à plusieurs espaces de nommage GitLab Duo et qu'aucun espace de nommage par défaut n'est défini, la plateforme GitLab Duo Agent est désactivée.

Dans GitLab 18.8 et les versions antérieures, le message d'erreur suivant peut s'afficher :

```plaintext
Something went wrong while requesting a review from GitLab Duo.
```

Dans GitLab 18.9 et les versions ultérieures, vous pourriez obtenir une erreur liée à l'espace de nommage.

Pour résoudre ce problème, [définissez un espace de nommage GitLab Duo par défaut](../profile/preferences.md#set-a-default-gitlab-duo-namespace).

## Erreur : `SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)` {#error-ssl-certificate-openssl-verify-result-unable-to-get-local-issuer-certificate-20}

Sur les instances GitLab Self-Managed qui utilisent des certificats CA personnalisés ou auto-signés, ce message peut s'afficher lorsque les jobs de la plateforme GitLab Duo Agent échouent lors du `git clone` initial (la phase `get_sources`).

Cela se produit car les jobs de la plateforme GitLab Duo Agent définissent `GIT_CONFIG_GLOBAL=/dev/null` et `GIT_CONFIG_NOSYSTEM=1` pour renforcer le sandbox de l'agent. Ces variables empêchent Git de lire les fichiers de configuration système et globaux. Cela interrompt le mécanisme du runner pour l'injection des chemins de certificats CA lors de `get_sources`.

Les jobs CI/CD qui n'exécutent pas de flows ne sont pas affectés. Ce problème est spécifique aux pipelines de workload de la plateforme GitLab Duo Agent.

Pour résoudre ce problème, dans le fichier [`config.toml`](https://docs.gitlab.com/runner/configuration/advanced-configuration/), définissez la variable d'environnement `GIT_SSL_CAINFO` au niveau du runner et montez le certificat CA dans le conteneur :

```toml
[[runners]]
  environment = ["GIT_SSL_CAINFO=/etc/gitlab-runner/certs/ca.crt"]
  [runners.docker]
    volumes = ["/path/to/your/ca-bundle.crt:/etc/gitlab-runner/certs/ca.crt:ro"]
```

Remplacez `/path/to/your/ca-bundle.crt` par le chemin d'accès à votre bundle de certificats CA sur l'hôte du runner. Le fichier doit être un bundle CA au format PEM contenant votre CA racine et tout certificat intermédiaire.

Vous pourriez vous attendre à définir ceci comme variable CI/CD, mais les variables CI/CD personnalisées [ne sont pas disponibles](flows/execution/execution-variables.md#custom-cicd-variables) dans les jobs de la plateforme GitLab Duo Agent. Vous devez utiliser la directive `config.toml` `environment` du runner à la place.

Pour connecter GitLab Duo CLI à votre instance GitLab via un CA personnalisé, ajoutez `NODE_EXTRA_CA_CERTS` à la même ligne `environment` :

```toml
[[runners]]
  environment = [
    "GIT_SSL_CAINFO=/etc/gitlab-runner/certs/ca.crt",
    "NODE_EXTRA_CA_CERTS=/etc/gitlab-runner/certs/ca.crt"
  ]
  [runners.docker]
    volumes = ["/path/to/your/ca-bundle.crt:/etc/gitlab-runner/certs/ca.crt:ro"]
```

Le CLI GitLab Duo s'exécute dans l'environnement Anthropic Sandbox Runtime (SRT), qui démarre avec un environnement vide. Lorsque les variables de certificat et de proxy suivantes sont définies dans le job, elles sont transmises dans le sandbox :

- `NODE_EXTRA_CA_CERTS`
- `HTTP_PROXY`, `HTTPS_PROXY` et `NO_PROXY`
- Les équivalents en minuscules `http_proxy`, `https_proxy` et `no_proxy`

Définissez ces variables dans la directive `environment` du runner, ou exportez-les dans le `setup_script` de votre fichier `agent-config.yml`. Les autres variables ne sont pas transmises.

Ces variables s'appliquent à tout le trafic réseau Node.js dans le sandbox, pas uniquement aux connexions à votre instance GitLab. `NODE_EXTRA_CA_CERTS` pointe vers un fichier, montez donc le certificat CA dans le conteneur comme indiqué précédemment.

`NODE_TLS_REJECT_UNAUTHORIZED` n'est pas transmis, car le définir à `0` désactive la vérification TLS. Utilisez plutôt `NODE_EXTRA_CA_CERTS`.

La variable `GIT_SSL_CAINFO` traite les opérations Git qui se produisent avant le démarrage du CLI GitLab Duo. Pour la configuration des certificats du CLI GitLab Duo, consultez [les erreurs de certificat](../gitlab_duo_cli/use.md#certificate-errors).

## La connexion échoue avec l'erreur WebSocket `1006` ou `404` {#connection-fails-with-websocket-error-1006-or-404}

Le CLI GitLab Duo, le serveur de langage GitLab et les clients IDE (GitLab pour VS Code, le plugin GitLab Duo pour les IDE JetBrains et GitLab pour Visual Studio) se connectent à la plateforme GitLab Duo Agent via une connexion WebSocket. Lorsque cette connexion échoue, le client journalise l'une des erreurs suivantes :

- `1006` : le WebSocket s'est fermé anormalement, sans fermeture de liaison.
- `404` : le client ne peut pas atteindre les points de terminaison WebSocket suivants :
  - Pour GitLab Duo Non-Agentique : `/-/cable`.
  - Pour la plateforme GitLab Duo Agent : `wss://\<instance\>/api/v4/ai/duo_workflows/ws`.

Ces erreurs surviennent généralement lorsqu'une autorité de certification (CA) personnalisée, un proxy HTTP, un proxy d'inspection TLS ou un proxy TLS mutuel (mTLS) sur votre réseau interfère avec la connexion. Pour résoudre ce problème, examinez les causes suivantes.

### Certificat CA personnalisé {#custom-ca-certificate}

Si votre réseau utilise un certificat CA personnalisé ou auto-signé, le client ne peut pas vérifier la connexion à votre instance GitLab. Configurez le certificat pour votre client :

- Pour le CLI GitLab Duo, définissez la variable d'environnement `NODE_EXTRA_CA_CERTS` sur le chemin d'accès à votre certificat CA.
- Pour les clients IDE, le serveur de langage GitLab gère le certificat. Pour les IDE JetBrains, consultez [les erreurs de certificat](../../editor_extensions/jetbrains_ide/jetbrains_troubleshooting.md#certificate-errors). Pour VS Code, consultez [les erreurs avec des certificats personnalisés](../../editor_extensions/visual_studio_code/troubleshooting.md#errors-with-custom-certificates).

### Proxy HTTP {#http-proxy}

Si votre réseau nécessite un proxy HTTP, configurez le proxy pour votre client :

- Pour le CLI GitLab Duo, définissez les variables d'environnement `HTTP_PROXY`, `HTTPS_PROXY` et `NO_PROXY`.
- Pour les clients IDE, [configurez le serveur de langage pour utiliser un proxy](../../editor_extensions/language_server/_index.md#configure-the-language-server-to-use-a-proxy).

### Trafic WebSocket bloqué {#websocket-traffic-blocked}

Si vous voyez une erreur `404`, ou des réponses `HTTP/1.1` à la place des points de terminaison WebSocket `/-/cable` dans vos journaux, votre instance GitLab pourrait bloquer les connexions WebSocket entrantes. Demandez à votre administrateur d'[autoriser le trafic WebSocket vers votre instance GitLab](../../administration/gitlab_duo/configure/_index.md#allow-inbound-connections-from-clients-to-the-gitlab-instance).

### Proxy mTLS ou d'inspection TLS {#mtls-or-tls-inspection-proxy}

Si votre réseau achemine le trafic via un proxy d'inspection TLS (interception SSL), configurez les deux éléments suivants :

- Définissez la variable d'environnement `HTTPS_PROXY` sur l'URL de votre proxy.
- Ajoutez le [certificat CA](#custom-ca-certificate) du proxy.

Le CLI GitLab Duo, le plugin GitLab Duo pour les IDE JetBrains et GitLab pour Visual Studio présentent un problème connu. Si l'URL du proxy utilise `https://`, la connexion WebSocket échoue. Utilisez une URL de proxy `http://` si possible.

GitLab pour VS Code n'est pas affecté.

## Dépannage dans votre IDE {#troubleshooting-in-your-ide}

Si vous rencontrez un problème lors de l'utilisation de la plateforme GitLab Duo Agent dans votre IDE, commencez par vérifier que GitLab Duo est activé et que vous êtes correctement connecté.

- Vous remplissez les [prérequis](_index.md#prerequisites) de la plateforme GitLab Duo Agent.
- Le mode administrateur est [désactivé](../../administration/settings/sign_in_restrictions.md#turn-off-admin-mode-for-your-session).
- Votre projet se trouve dans un [espace de nommage de groupe](../namespace/_index.md).
- Vous avez défini un [espace de nommage GitLab Duo par défaut](../profile/preferences.md#namespace-resolution-in-your-local-environment) ou vous avez un projet ouvert qui dispose d'un accès GitLab Duo.

Pour obtenir de l'aide supplémentaire, consultez la page de dépannage de votre extension et IDE :

- [GitLab pour VS Code](../../editor_extensions/visual_studio_code/troubleshooting.md#gitlab-duo)
- [Plugin GitLab Duo pour les IDE JetBrains](../../editor_extensions/jetbrains_ide/jetbrains_troubleshooting.md)
- [GitLab pour Visual Studio](../../editor_extensions/visual_studio/visual_studio_troubleshooting.md)

## Exécuter le script de diagnostic de configuration {#run-the-configuration-diagnostic-script}

Si vous ne parvenez pas à identifier la cause d'un problème lié à la plateforme GitLab Duo Agent à partir de la documentation relative à la fonctionnalité, exécutez le script de diagnostic pour vérifier votre configuration.

Le script vérifie l'intégralité de la chaîne de configuration requise pour les fonctionnalités de la plateforme GitLab Duo Agent :

- Validité de la licence et plan.
- Paramètres GitLab Duo au niveau de l'instance.
- Runners CI/CD avec le tag `gitlab--duo`.
- Paramètres GitLab Duo de l'espace de nommage et du projet.
- Flows par défaut et leurs comptes de service.
- Disponibilité des fonctionnalités, notamment la disponibilité du flow Code Review et les paramètres de révision automatique.

> [!warning]
> Ce script lit uniquement les données de configuration et ne modifie aucun paramètre. La sortie peut contenir des détails de configuration interne. Nettoyez la sortie avant de la partager avec le support.

Prérequis :

- GitLab 18.8 ou version ultérieure

Pour exécuter le script de diagnostic dans GitLab 19.0 ou version ultérieure :

- Exécutez la [tâche Rake](../../administration/raketasks/_index.md) intégrée `gitlab:duo:verify_setup`. Remplacez `<group/project>` par le chemin complet du projet, par exemple `gitlab-org/gitlab`.

  Par exemple :

  ```shell
  sudo gitlab-rake "gitlab:duo:verify_setup[<group/project>]"
  ```

Pour exécuter le script de diagnostic dans GitLab 18.8 à GitLab 18.11 :

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

1. Téléchargez [`verify_setup.rb`](https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/lib/gitlab/duo/administration/verify_setup.rb).
1. Copiez le fichier `verify_setup.rb` sur votre serveur GitLab.
1. Exécutez le script. Remplacez `<group/project>` par le chemin complet du projet, par exemple `gitlab-org/gitlab`.

   ```shell
   sudo gitlab-rails runner "load '/tmp/verify_setup.rb'; Gitlab::Duo::Administration::VerifySetup.new('<group/project>').execute"
   ```

{{< /tab >}}

{{< tab title="Docker" >}}

1. Téléchargez [`verify_setup.rb`](https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/lib/gitlab/duo/administration/verify_setup.rb).
1. Copiez le fichier `verify_setup.rb` dans le conteneur.
1. Exécutez le script. Remplacez `<group/project>` par le chemin complet du projet, par exemple `gitlab-org/gitlab`.

   ```shell
   docker cp verify_setup.rb <container-id>:/tmp/verify_setup.rb
   docker exec -it <container-id> gitlab-rails runner \
   "load '/tmp/verify_setup.rb'; Gitlab::Duo::Administration::VerifySetup.new('<group/project>').execute"
   ```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

1. Téléchargez [`verify_setup.rb`](https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/lib/gitlab/duo/administration/verify_setup.rb).
1. Copiez le fichier `verify_setup.rb` sur votre serveur GitLab.
1. Exécutez le script depuis le répertoire de l'application GitLab. Remplacez `<group/project>` par le chemin complet du projet, par exemple `gitlab-org/gitlab`.

   ```shell
   sudo -u git bundle exec rails runner \
   "load '/tmp/verify_setup.rb'; Gitlab::Duo::Administration::VerifySetup.new('<group/project>').execute"
   ```

{{< /tab >}}

{{< tab title="Chart Helm (Kubernetes)" >}}

1. Téléchargez [`verify_setup.rb`](https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/lib/gitlab/duo/administration/verify_setup.rb).
1. Copiez le fichier `verify_setup.rb` dans le pod toolbox.
1. Exécutez le script. Remplacez `<group/project>` par le chemin complet du projet, par exemple `gitlab-org/gitlab`.

   ```shell
   # Find the toolbox pod
   kubectl get pods --namespace <namespace> -lapp=toolbox

   kubectl cp verify_setup.rb <namespace>/<toolbox-pod-name>:/tmp/verify_setup.rb
   kubectl exec -it <toolbox-pod-name> -- gitlab-rails runner \
   "load '/tmp/verify_setup.rb'; Gitlab::Duo::Administration::VerifySetup.new('<group/project>').execute"
   ```

{{< /tab >}}

{{< /tabs >}}

## Sujets connexes {#related-topics}

- [Dépannage de GitLab Duo Agentic Chat](../gitlab_duo_chat/troubleshooting.md)
- [Dépannage du flow Code Review](flows/foundational_flows/code_review/troubleshooting.md)
- [Dépannage des clients GitLab MCP](../gitlab_duo/model_context_protocol/mcp_clients.md#troubleshooting)
- [Dépannage du serveur GitLab MCP](../model_context_protocol/mcp_server_troubleshooting.md)
