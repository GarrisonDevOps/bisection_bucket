---
stage: AI Platform
group: AI Model Services
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Dépannage de GitLab Duo
---

Lorsque vous utilisez GitLab Duo, vous pouvez rencontrer des problèmes.

Commencez par [exécuter un bilan de santé](../../administration/gitlab_duo/configure/_index.md#run-a-health-check-for-gitlab-duo) pour déterminer si votre instance répond aux exigences d'utilisation de GitLab Duo.

Pour plus d'informations sur le dépannage de GitLab Duo, consultez :

- [Dépannage des suggestions de code](../project/repository/code_suggestions/troubleshooting.md).
- [Dépannage de GitLab Duo Chat](../gitlab_duo_chat/troubleshooting.md).
- [Dépannage de GitLab Duo auto-hébergé](../../administration/gitlab_duo_self_hosted/troubleshooting.md).

Si le bilan de santé ne résout pas votre problème, passez en revue ces étapes de dépannage.

## Les fonctionnalités de GitLab Duo ne fonctionnent pas sur les instances auto-hébergées {#gitlab-duo-features-do-not-work-on-self-managed}

En plus de [vous assurer que les fonctionnalités GitLab Duo sont activées](turn_on_off.md), vous pouvez également effectuer les opérations suivantes :

1. En tant qu'administrateur, exécutez un bilan de santé pour GitLab Duo.

   {{< tabs >}}

   {{< tab title="Dans la version 17.5 et ultérieures" >}}

   Dans GitLab 17.5 et versions ultérieures, vous pouvez utiliser l'interface utilisateur pour exécuter des bilans de santé et télécharger un rapport détaillé qui aide à identifier et à résoudre les problèmes.

   {{< /tab >}}

   {{< tab title="Dans la version 17.4" >}}

   Dans GitLab 17.4, vous pouvez exécuter la tâche Rake de bilan de santé pour générer un rapport détaillé qui aide à identifier et à résoudre les problèmes.

   ```shell
   sudo gitlab-rails 'cloud_connector:health_check(root,report.json)'
   ```

   {{< /tab >}}

   {{< tab title="Dans la version 17.3 et les versions antérieures" >}}

   Dans GitLab 17.3 et versions antérieures, vous pouvez télécharger et exécuter le script `health_check` pour générer un rapport détaillé qui aide à identifier et à résoudre les problèmes.

   1. Téléchargez le script de bilan de santé :

      ```shell
      wget https://gitlab.com/gitlab-org/gitlab/-/snippets/3734617/raw/main/health_check.rb
      ```

   1. Exécutez le script à l'aide de Rails Runner :

      ```shell
      gitlab-rails runner [full_path/to/health_check.rb] --debug --username [username] --output-file [report.txt]
      ```

      ```shell
      Usage: gitlab-rails runner full_path/to/health_check.rb
             --debug                Enable debug mode
             --output-file FILE     Write a report to FILE
             --username USERNAME    Provide a username to test seat assignments
             --skip [CHECK]         Skip specific check (options: access_data, token, license, host, features, end_to_end)
      ```

   {{< /tab >}}

   {{< /tabs >}}

1. Vérifiez que l'instance GitLab peut atteindre les [points de terminaison GitLab.com requis](../../administration/gitlab_duo/configure/_index.md). Vous pouvez utiliser des outils de ligne de commande tels que `curl` pour vérifier la connectivité.

   ```shell
   curl --verbose "https://cloud.gitlab.com"

   curl --verbose "https://customers.gitlab.com"
   ```

   Si un proxy HTTP/S est configuré pour l'instance GitLab, incluez le paramètre `proxy` dans la commande `curl`.

   ```shell
   # https proxy for curl
   curl --verbose --proxy "http://USERNAME:PASSWORD@example.com:8080" "https://cloud.gitlab.com"
   curl --verbose --proxy "http://USERNAME:PASSWORD@example.com:8080" "https://customers.gitlab.com"
   ```

1. Facultatif. Si vous utilisez un [serveur proxy](../../administration/gitlab_duo/configure/_index.md#allow-outbound-connections-from-the-gitlab-instance-to-gitlab-duo) entre l'application GitLab et l'internet public, [désactivez la protection contre le rebinding DNS](../../security/webhooks.md#enforce-dns-rebinding-attack-protection).

1. [Synchronisez manuellement les données d'abonnement](../../subscriptions/manage_subscription.md#manually-synchronize-subscription-data).
   - Vérifiez que l'instance GitLab [synchronise vos données d'abonnement avec GitLab](https://about.gitlab.com/pricing/licensing-faq/cloud-licensing/).

## Erreur : `Webview didn't initialize in 10000ms` {#error-webview-didnt-initialize-in-10000ms}

Vous pouvez rencontrer cette erreur lors de l'utilisation de GitLab Duo Chat dans des sessions VS Code Remote SSH ou WSL. L'extension peut également tenter de se connecter de manière incorrecte à une adresse `127.0.0.1`.

Ce problème survient lorsque des environnements distants introduisent une latence qui dépasse le délai d'expiration codé en dur de 10 secondes dans GitLab VS Code Extension 6.8.0 et versions ultérieures.

Pour résoudre ce problème :

1. Dans VS Code, ouvrez l'éditeur de paramètres :
   - Pour macOS, appuyez sur <kbd>Commande</kbd>+<kbd>,</kbd>.
   - Pour Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>,</kbd>.
1. Sélectionnez **Open Settings (JSON)** pour modifier votre fichier `settings.json`. Vous pouvez également appuyer sur <kbd>F1</kbd>, saisir **Preferences : Open Settings (JSON)**, puis le sélectionner.
1. Ajoutez ce paramètre :

   ```json
   "gitlab.featureFlags.languageServerWebviews": false
   ```

1. Enregistrez et rechargez VS Code.

## Dépannage de GitLab Duo sur GitLab Dedicated {#troubleshooting-gitlab-duo-on-gitlab-dedicated}

GitLab Duo Core devrait fonctionner immédiatement dans GitLab 18.3 et versions ultérieures pour les clients GitLab Premium et GitLab Ultimate, pour toutes les fonctionnalités de GitLab Duo à l'exception de GitLab Duo Non-Agentic Chat.

Par conception, les instances GitLab Dedicated de pré-production ne prennent pas en charge GitLab Duo Core.

### Les paramètres GitLab Duo ne sont pas visibles dans la zone d'administration {#gitlab-duo-settings-not-visible-in-admin-area}

Vous pouvez rencontrer un ou plusieurs de ces problèmes :

- La section **GitLab Duo** n'apparaît pas dans la zone d'administration.
- Des options de configuration sont manquantes.
- Les appels API renvoient `"addOnPurchases": []`.

Ces problèmes surviennent lorsque votre licence n'est pas correctement synchronisée avec l'instance.

Pour résoudre ce problème, créez un ticket d'assistance afin de vérifier la synchronisation des licences. L'assistance peut vérifier le statut de synchronisation et demander une nouvelle génération de licence si nécessaire.

### Erreur : `GitLab-workflow failed: the GitLab Language server failed to start in 10 seconds` {#error-gitlab-workflow-failed-the-gitlab-language-server-failed-to-start-in-10-seconds}

Vous pouvez rencontrer cette erreur lorsque vous utilisez GitLab Duo Chat dans le Web IDE. Vous pourriez également voir des erreurs de console concernant `Platform is missing!`

Ce problème survient lorsque la connectivité réseau vers `cloud.gitlab.com` et `customers.gitlab.com` est bloquée par la configuration réseau.

Pour résoudre ce problème :

1. Vérifiez les connexions sortantes vers `cloud.gitlab.com:443` et `customers.gitlab.com:443`.
1. Ajoutez les [plages IP Cloudflare](https://www.cloudflare.com/ips/) à votre liste d'autorisation si nécessaire.
1. Vérifiez les restrictions de liste d'autorisation ou de pare-feu avec le [lien privé](../../administration/dedicated/configure_instance/network_security.md#aws-privatelink-connectivity).
1. Suivez le guide de [filtrage des requêtes sortantes](../../security/webhooks.md#gitlab-duo-functionality-is-blocked) pour résoudre les problèmes de connectivité.
1. Testez la connectivité depuis l'instance.

### Erreur : `Unable to resolve resource` {#error-unable-to-resolve-resource}

Vous pouvez rencontrer cette erreur lorsque le Web IDE ne parvient pas à se charger. Consultez les journaux du navigateur pour les erreurs CORS : `failed to load because it violates the following Content Security policy`.

Ce problème survient lorsque les politiques CORS bloquent les ressources requises.

Pour résoudre ce problème :

1. Mettez à jour vers GitLab pour VS Code version 6.35.1 ou ultérieure.
1. Ajoutez `https://*.cdn.web-ide.gitlab-static.net` à votre politique CORS.
1. Pour approfondir le dépannage, consultez les fichiers HAR pour les journaux. Pour plus d'informations, consultez [créer des fichiers HAR](../application_security/api_fuzzing/create_har_files.md).

Pour plus d'informations, consultez [Problèmes CORS](../project/web_ide/_index.md#cors-issues).

## Fonctionnalités de GitLab Duo non disponibles pour les utilisateurs {#gitlab-duo-features-not-available-for-users}

En plus d'[activer les fonctionnalités GitLab Duo](turn_on_off.md), vous pouvez également effectuer les opérations suivantes :

- Si vous disposez de GitLab Duo Core, vérifiez que vous avez :
  - D'un abonnement GitLab Premium ou GitLab Ultimate.
  - [Activé les fonctionnalités IDE](turn_on_off.md#turn-gitlab-duo-core-on-or-off).
  > [!note]
  > GitLab Duo Non-Agentic Chat n'est pas disponible pour les utilisateurs de GitLab Duo Core.
- Si vous disposez de GitLab Duo Pro ou Enterprise :
  - Vérifiez qu'[un module complémentaire d'abonnement a été acheté](../../subscriptions/subscription-add-ons.md#purchase-gitlab-duo).
  - Assurez-vous que [des sièges sont attribués aux utilisateurs](../../subscriptions/subscription-add-ons.md#assign-gitlab-duo-seats).
- Pour votre IDE :
  - Vérifiez que l'[extension](../project/repository/code_suggestions/set_up.md#configure-an-editor-extension) ou le plugin est à jour.
  - Exécutez des bilans de santé et testez l'authentification.
