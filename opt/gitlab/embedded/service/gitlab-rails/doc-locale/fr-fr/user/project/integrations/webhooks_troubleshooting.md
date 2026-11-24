---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Rappels HTTP personnalisés, utilisés pour envoyer des événements."
title: Dépannage des webhooks
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Résolvez les problèmes courants liés aux webhooks GitLab.

## Déboguer les webhooks {#debug-webhooks}

Déboguez les webhooks GitLab et capturez les charges utiles à l'aide des méthodes suivantes :

- [Outils publics d'inspection des webhooks](#use-public-webhook-inspection-tools)
- [Détails des requêtes et des réponses des webhooks](webhooks.md#inspect-request-and-response-details)
- [GitLab Development Kit (GDK)](#use-the-gitlab-development-kit-gdk)
- [Récepteur de webhook privé](#create-a-private-webhook-receiver)

Pour en savoir plus sur les événements de webhook et les charges utiles JSON, consultez [les événements de webhook](webhook_events.md).

### Utiliser des outils publics d'inspection des webhooks {#use-public-webhook-inspection-tools}

Utilisez des outils publics pour inspecter et tester les charges utiles des webhooks. Ces outils fournissent des points de terminaison universels pour les requêtes HTTP et répondent avec un code de statut `200 OK`.

> [!warning]
> Faites preuve de prudence lorsque vous utilisez des outils publics, car vous pourriez envoyer des données sensibles à des services externes. Utilisez des jetons de test et renouvelez tout secret envoyé par inadvertance à des tiers. Pour une confidentialité renforcée, [créez un récepteur de webhook privé](#create-a-private-webhook-receiver).

Les outils publics d'inspection des webhooks comprennent :

<!-- vale gitlab_base.Spelling = NO -->
- [Beeceptor](https://beeceptor.com) : créez un point de terminaison HTTPS temporaire et inspectez les charges utiles entrantes.
<!-- vale gitlab_base.Spelling = YES -->
- [Webhook.site](https://webhook.site) : examinez les charges utiles entrantes.
- [Webhook Tester](https://webhook-test.com) : inspectez et déboguez les charges utiles entrantes.

### Utiliser le GitLab Development Kit (GDK) {#use-the-gitlab-development-kit-gdk}

Pour un environnement de développement plus sûr, utilisez le [GitLab Development Kit (GDK)](https://gitlab.com/gitlab-org/gitlab-development-kit) pour travailler avec les webhooks GitLab en local. Utilisez le GDK pour envoyer des webhooks depuis votre instance GitLab locale vers un récepteur de webhook sur votre machine.

Pour utiliser cette approche, installez et configurez le GDK.

### Créer un récepteur de webhook privé {#create-a-private-webhook-receiver}

Créez votre propre récepteur de webhook privé si vous ne pouvez pas envoyer de charges utiles de webhook à un [récepteur public](#use-public-webhook-inspection-tools).

Prérequis :

- Ruby est installé sur votre système.

Pour créer un récepteur de webhook privé :

1. Enregistrez ce script sous `print_http_body.rb` :

   ```ruby
   require 'webrick'

   server = WEBrick::HTTPServer.new(:Port => ARGV.first)
   server.mount_proc '/' do |req, res|
     puts req.body
   end

   trap 'INT' do
     server.shutdown
   end
   server.start
   ```

1. Choisissez un port inutilisé (par exemple, `8000`) et démarrez le script :

   ```shell
   ruby print_http_body.rb 8000
   ```

1. Dans GitLab, [configurez le webhook](webhooks.md#configure-webhooks) avec l'URL de votre récepteur (par exemple, `http://receiver.example.com:8000/`).
1. Sélectionnez **Test**. Vous devriez voir une sortie similaire à :

   ```plaintext
   {"before":"077a85dd266e6f3573ef7e9ef8ce3343ad659c4e","after":"95cd4a99e93bc4bbabacfa2cd10e6725b1403c60",<SNIP>}
   example.com - - [14/May/2014:07:45:26 EDT] "POST / HTTP/1.1" 200 0
   - -> /
   ```

> [!note]
> Pour ajouter ce récepteur, vous devrez peut-être [autoriser les requêtes vers le réseau local](../../../security/webhooks.md).

## Résoudre les erreurs de vérification du certificat SSL {#resolve-ssl-certificate-verification-errors}

Lorsque la vérification SSL est activée, GitLab peut ne pas parvenir à vérifier le certificat SSL du point de terminaison du webhook et afficher l'erreur suivante :

```plaintext
unable to get local issuer certificate
```

Cette erreur se produit généralement lorsque le certificat racine n'est pas émis par une autorité de certification de confiance, telle que déterminée par [CAcert.org](http://www.cacert.org/).

Pour résoudre ce problème :

1. Utilisez [SSL Checker](https://www.sslshopper.com/ssl-checker.html) pour identifier les erreurs spécifiques.
1. Vérifiez l'absence de certificats intermédiaires, cause fréquente des échecs de vérification.

## Webhook non déclenché {#webhook-not-triggered}

Si un webhook n'est pas déclenché, vérifiez que :

- Le webhook n'est pas [désactivé automatiquement](webhooks.md#auto-disabled-webhooks).
- L'instance GitLab n'est pas en [mode silencieux](../../../administration/silent_mode/_index.md).
- Les paramètres **Limite des activités d'événement push** et **Limite des hooks d'événement push** dans la [zone **Admin**](../../../administration/settings/push_event_activities_limit.md) sont définis sur une valeur supérieure à `0`.

## Erreur : `Webhook rate limit exceeded` {#error-webhook-rate-limit-exceeded}

Un webhook peut échouer en raison d'une limite de débit. GitLab.com limite le nombre total d'appels de webhook par minute pour chaque espace de nommage de niveau supérieur. Pour plus d'informations, consultez [les limites de débit](../../gitlab_com/_index.md#rate-limits).

Pour confirmer si la limite de débit est en cause :

1. Consultez vos journaux GitLab pour le message `Webhook rate limit exceeded`.
1. Réduisez le nombre d'événements qui déclenchent des webhooks ou contactez le support GitLab pour discuter de vos exigences en matière de limite de débit.

## Le modèle de webhook personnalisé avec des espaces réservés non mis entre guillemets ne peut pas être enregistré {#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved}

Dans GitLab 18.8 à 18.10, les [modèles de webhook personnalisés](webhooks.md#custom-webhook-template) dont les champs de charge utile ne sont pas mis entre guillemets ne peuvent pas être enregistrés. Ce problème a été résolu dans GitLab 18.11. Pour contourner ce problème, mettez les champs entre guillemets ou effectuez une mise à niveau vers GitLab 18.11 ou une version ultérieure. Par exemple, `{"value": {{id}}}` deviendrait `{"value": "{{id}}"}`.

Les champs mis entre guillemets produisent des valeurs de type chaîne au lieu de valeurs numériques. Si cela est incompatible avec votre webhook et que vous devez y apporter des modifications, il est recommandé d'effectuer une mise à niveau.

## Alertes en double d'échec de déploiement après un rejet {#duplicate-deployment-failure-alerts-after-a-rejection}

Lorsqu'un déploiement vers un [environnement protégé](../../../ci/environments/deployment_approvals.md) est rejeté, GitLab envoie un webhook `status: "rejected"`, suivi d'un webhook `status: "failed"` pour le même `deployment_id` lorsque le job de déploiement est abandonné. L'événement `failed` est l'événement du cycle de vie existant et n'inclut pas les champs d'approbation ; ainsi, un récepteur qui génère des alertes sur `status: "failed"` peut déclencher une alerte en double pour un déploiement intentionnellement rejeté.

Pour éviter les alertes en double :

1. Corrélez les événements par `deployment_id` et traitez un événement `status: "failed"` qui suit un événement `status: "rejected"` pour le même déploiement comme un seul et même événement.
1. Pour distinguer les échecs dus à un rejet des échecs réels, écoutez l'événement `status: "rejected"` et stockez les identifiants de déploiement qui ont été rejetés. Lorsqu'un événement `status: "failed"` arrive, supprimez l'alerte si son `deployment_id` fait partie de cet ensemble.
