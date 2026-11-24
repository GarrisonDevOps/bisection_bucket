---
stage: AI Platform
group: AI Core Infra
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Résoudre les problèmes liés à la passerelle d'IA."
title: "Dépannage de la passerelle d'IA"
---

Lorsque vous utilisez la [passerelle d'IA](install_ai_gateway.md), vous pouvez rencontrer les problèmes suivants.

## Problèmes de permissions OpenShift {#openshift-permission-issues}

Lors du déploiement de la passerelle d'IA sur OpenShift, vous pouvez rencontrer des erreurs de permissions dues au modèle de sécurité d'OpenShift.

### Système de fichiers en lecture seule sur `/tmp` {#read-only-file-system-at-tmp}

La passerelle d'IA écrit dans `/tmp`. Cependant, selon l'environnement OpenShift, qui est soumis à des restrictions de sécurité, `/tmp` peut être en lecture seule.

Pour résoudre ce problème, créez un nouveau volume `EmptyDir` et montez-le sur `/tmp` de l'une des manières suivantes :

- Depuis la ligne de commande :

  ```shell
  oc set volume <object_type>/<name> --add --name=tmpVol --type=emptyDir --mountPoint=/tmp
  ```

- Dans votre `values.yaml` :

  ```yaml
  volumes:
  - name: tmp-volume
    emptyDir: {}

  volumeMounts:
  - name: tmp-volume
    mountPath: "/tmp"
  ```

### Modèles HuggingFace {#huggingface-models}

Par défaut, la passerelle d'IA utilise `/home/aigateway/.hf` pour mettre en cache les modèles HuggingFace, ce qui peut ne pas être accessible en écriture dans l'environnement soumis à des restrictions de sécurité d'OpenShift. Des erreurs de permissions similaires à celle-ci peuvent survenir :

```shell
[Errno 13] Permission denied: '/home/aigateway/.hf/...'
```

Pour résoudre ce problème, définissez la variable d'environnement `HF_HOME` sur un emplacement accessible en écriture. Vous pouvez utiliser `/var/tmp/huggingface` ou tout autre répertoire accessible en écriture par le conteneur, de l'une des manières suivantes :

- Dans votre `values.yaml` :

  ```yaml
  extraEnvironmentVariables:
    - name: HF_HOME
      value: /var/tmp/huggingface  # Use any writable directory
  ```

- Dans votre commande de mise à niveau Helm :

  ```shell
  --set "extraEnvironmentVariables[0].name=HF_HOME" \
  --set "extraEnvironmentVariables[0].value=/var/tmp/huggingface"  # Use any writable directory
  ```

Cette configuration permet à la passerelle d'IA de mettre correctement en cache les modèles HuggingFace tout en respectant les contraintes de sécurité d'OpenShift. Le répertoire exact que vous choisissez peut dépendre de votre configuration OpenShift spécifique et de vos politiques de sécurité.

## Cache du tokenizer masqué par un point de montage de volume {#tokenizer-cache-shadowed-by-a-volume-mount}

Les fichiers de tokenizer pré-mis en cache dans l'image de la passerelle d'IA peuvent être masqués par un point de montage de volume si :

- Les requêtes de complétion de code renvoient une erreur `500`.
- Les journaux de la passerelle d'IA affichent une erreur `OSError` provenant de `transformers/utils/hub.py` lors d'une tentative de téléchargement de `Salesforce/codegen2-16B` depuis `huggingface.co`.

L'image auto-hébergée de la passerelle d'IA (`self-hosted-vX.Y.Z-ee`) définit `HF_HUB_OFFLINE=true` et pré-met en cache le tokenizer au moment de la compilation, de sorte qu'aucun accès réseau à `huggingface.co` ne devrait se produire à l'exécution. Si un accès réseau se produit, un répertoire vide dans vos valeurs Helm peut être monté sur `/home/aigateway/.hf`, écrasant les fichiers mis en cache.

N'essayez pas de résoudre ce problème en accordant un accès sortant à `huggingface.co`. Au lieu de cela, pour diagnostiquer le problème, exécutez la commande suivante dans le pod de la passerelle d'IA :

```shell
ls -la /home/aigateway/.hf/hub/ 2>/dev/null || echo "NO_CACHE_DIR"
env | grep -E '^(HF_|TRANSFORMERS_)'
```

Si le répertoire de cache est manquant ou vide, procédez comme suit :

1. Vérifiez votre `values.yaml` pour tout `volumeMounts` ciblant `/home/aigateway/.hf` ou le chemin défini par `HF_HOME`.
1. Supprimez ou remappez le point de montage vers un répertoire qui ne chevauche pas le cache intégré à l'image.

## Erreur de certificat auto-signé {#self-signed-certificate-error}

Lorsque la passerelle d'IA tente de se connecter à une instance GitLab ou à un point de terminaison de modèle avec un certificat signé par une autorité de certification (CA) personnalisée ou un certificat auto-signé, l'erreur suivante peut se produire :

```plaintext
[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate in certificate chain
```

Pour résoudre ce problème, consultez la section [se connecter à une instance GitLab ou à un point de terminaison de modèle avec un certificat SSL auto-signé](install_ai_gateway.md#connect-to-a-gitlab-instance-or-model-endpoint-with-a-self-signed-ssl-certificate).

## Échec de la création du jeton {#token-creation-failed}

Si vous rencontrez une erreur `Token creation failed` lors de l'utilisation de fonctionnalités telles que GitLab Duo Chat, les variables d'environnement `AIGW_SELF_SIGNED_JWT__SIGNING_KEY` et `AIGW_SELF_SIGNED_JWT__VALIDATION_KEY` peuvent ne pas être définies sur la passerelle d'IA.

Ces clés sont requises pour que la passerelle d'IA puisse émettre des JWT utilisateur de courte durée. Sans ces clés, la passerelle d'IA ne peut pas signer les jetons, ce qui entraîne un échec de désérialisation JWK.

Pour résoudre ce problème :

1. Générez les clés requises :

   ```shell
   openssl genrsa -out aigw_signing.key 2048
   openssl genrsa -out aigw_validation.key 2048
   ```

1. Ajoutez les clés à votre conteneur de passerelle d'IA en les transmettant comme variables d'environnement :

   ```shell
   -e AIGW_SELF_SIGNED_JWT__SIGNING_KEY="$(cat aigw_signing.key)" \
   -e AIGW_SELF_SIGNED_JWT__VALIDATION_KEY="$(cat aigw_validation.key)"
   ```

1. Redémarrez le conteneur de la passerelle d'IA.

## Erreurs de certificat SSL lors du chargement de fichiers PEM {#ssl-certificate-errors-when-loading-pem-files}

Si vous obtenez une erreur indiquant `JWKError` lors du chargement du fichier PEM dans le conteneur Docker, vous devrez peut-être résoudre une erreur de certificat SSL.

Pour résoudre ce problème, utilisez les variables d'environnement suivantes pour définir le chemin d'accès approprié au bundle de certificats dans le conteneur Docker :

- `SSL_CERT_FILE=/path/to/ca-bundle.pem`
- `REQUESTS_CA_BUNDLE=/path/to/ca-bundle.pem`

Remplacez `/path/to/ca-bundle.pem` par le chemin d'accès à votre bundle de certificats.

## Erreurs lors de l'envoi d'événements de facturation à une instance GitLab hors ligne {#errors-when-sending-billing-events-to-an-offline-gitlab-instance}

Dans un environnement hors ligne, la passerelle d'IA envoie des événements au point de terminaison API `/api/v4/ai/billable_usage/events` de votre instance GitLab. Si une requête échoue, vérifiez le statut de la réponse dans les journaux de la passerelle d'IA :

- `401` : `AIGW_BILLING_EVENT__API_KEY` n'est pas défini, ou le jeton est invalide.
- `403` : le jeton ne possède pas la [portée `ai_features`](../security/tokens/access_token_scopes.md) ou n'appartient pas à un [compte de service](../user/profile/service_accounts.md#create-a-service-account).
- `404` : le feature flag `local_billing_persistence` est désactivé, ou l'instance GitLab n'utilise pas de licence hors ligne.

Pour plus d'informations, consultez la section [envoyer des événements de facturation à votre instance GitLab](install_ai_gateway.md#send-billing-events-to-an-offline-gitlab-instance).
