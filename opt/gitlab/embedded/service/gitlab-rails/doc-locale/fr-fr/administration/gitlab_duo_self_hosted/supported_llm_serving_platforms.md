---
stage: AI Platform
group: AI Model Services
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Plateformes prises en charge pour servir des LLM.
title: Configurer les plateformes LLM
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Module d'extension : GitLab Duo Enterprise
- Offre : GitLab Self-Managed, GitLab Dedicated, GitLab Dedicated for Government

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/12972) dans GitLab 17.1 [avec le feature flag](../feature_flags/_index.md) `ai_custom_model`. Fonctionnalité désactivée par défaut.
- [Activation sur GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/168171) dans GitLab 17.5.
- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171692) : l'extension GitLab Duo Enterprise est désormais requise dans GitLab 17.6.
- Le feature flag `ai_custom_model` a été [supprimé](https://gitlab.com/gitlab-org/gitlab/-/work_items/498194) dans GitLab 17.8.
- [Disponibilité générale](https://gitlab.com/groups/gitlab-org/-/work_items/15176) dans GitLab 17.9.
- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/188263) : GitLab Premium est désormais inclus dans GitLab 18.0.

{{< /history >}}

La passerelle d'IA prend en charge plusieurs fournisseurs de LLM au moyen de [LiteLLM](https://docs.litellm.ai/docs/providers). GitLab a validé et testé les plateformes suivantes.

Si la plateforme que vous souhaitez utiliser n'est pas répertoriée, partagez vos commentaires dans [le ticket 526144](https://gitlab.com/gitlab-org/gitlab/-/work_items/526144).

## Utiliser plusieurs modèles et plateformes {#use-multiple-models-and-platforms}

Vous pouvez utiliser plusieurs modèles et plateformes dans la même instance GitLab.

Par exemple, vous pouvez configurer une fonctionnalité pour qu'elle utilise Azure OpenAI et une autre pour qu'elle utilise AWS Bedrock ou des modèles auto-hébergés servis par vLLM.

Cette configuration vous permet de choisir le modèle et la plateforme les mieux adaptés à chaque cas d'utilisation. Les modèles doivent être pris en charge et servis par une plateforme compatible.

## Déploiements de modèles auto-hébergés {#self-hosted-model-deployments}

### vLLM {#vllm}

[vLLM](https://docs.vllm.ai/en/latest/index.html) est un serveur d'inférence à hautes performances optimisé pour servir des LLM en utilisant efficacement la mémoire. Il prend en charge le parallélisme de modèles et s'intègre facilement aux flux de travail existants.

Pour installer vLLM, consultez le [Guide d'installation de vLLM](https://docs.vllm.ai/en/latest/getting_started/installation/). Vous devriez installer la [version v0.18.1](https://github.com/vllm-project/vllm/releases/tag/v0.18.1) ou une version ultérieure.

Pour obtenir des instructions précises sur la configuration à appliquer pour servir GPT OSS 120B avec vLLM, consultez [Servir GPT OSS 120B avec vLLM](vllm_gpt_oss_120b.md).

#### Configuration de l'URL du point de terminaison {#configuring-the-endpoint-url}

Lors de la configuration de l'URL du point de terminaison pour toute plateforme compatible avec l'API OpenAI (comme vLLM) dans GitLab :

- L'URL doit se terminer par `/v1`
- Si vous utilisez la configuration vLLM par défaut, l'URL du point de terminaison serait `https://<hostname>:8000/v1`
- Si votre serveur est configuré derrière un proxy ou un équilibreur de charge, vous n'aurez peut-être pas besoin de spécifier le port, auquel cas l'URL serait `https://<hostname>/v1`

#### Trouver le nom du modèle {#find-the-model-name}

Une fois le modèle déployé, interrogez le point de terminaison `/v1/models` du serveur vLLM pour obtenir le nom à utiliser dans le champ de l'identifiant du modèle dans GitLab :

```shell
curl \
  --header "Authorization: Bearer API_KEY" \
  --header "Content-Type: application/json" \
  http://your-vllm-server:8000/v1/models
```

Le nom du modèle est la valeur du champ `data.id` dans la réponse.

Exemple de réponse :

```json
{
  "object": "list",
  "data": [
    {
      "id": "Mixtral-8x22B-Instruct-v0.1",
      "object": "model",
      "created": 1739421415,
      "owned_by": "vllm",
      "root": "mistralai/Mixtral-8x22B-Instruct-v0.1",
      // Additional fields removed for readability
    }
  ]
}
```

Dans cet exemple, si le `id` du modèle est `Mixtral-8x22B-Instruct-v0.1`, vous utiliseriez `custom_openai/Mixtral-8x22B-Instruct-v0.1` comme identifiant du modèle dans GitLab.

Pour plus d'informations, consultez la documentation suivante :

- Pour connaître les modèles pris en charge par vLLM, consultez la [documentation sur les modèles pris en charge par vLLM](https://docs.vllm.ai/en/latest/models/supported_models/).
- Pour connaître les options disponibles lorsque vous exécutez un modèle avec vLLM, consultez la [documentation de vLLM sur les arguments du moteur](https://docs.vllm.ai/en/stable/configuration/engine_args/).

#### Mistral-7B-Instruct-v0.2 {#mistral-7b-instruct-v02}

1. Téléchargez le modèle depuis HuggingFace :

   ```shell
   git clone https://<your-hugging-face-username>:<your-hugging-face-token>@huggingface.co/mistralai/Mistral-7B-Instruct-v0.3
   ```

1. Exécutez le serveur :

   ```shell
   vllm serve <path-to-model>/Mistral-7B-Instruct-v0.3 \
      --served_model_name <choose-a-name-for-the-model>  \
      --tokenizer_mode mistral \
      --tensor_parallel_size <number-of-gpus> \
      --load_format mistral \
      --config_format mistral \
      --tokenizer <path-to-model>/Mistral-7B-Instruct-v0.3
   ```

#### Mixtral-8x7B-Instruct-v0.1 {#mixtral-8x7b-instruct-v01}

1. Téléchargez le modèle depuis HuggingFace :

   ```shell
   git clone https://<your-hugging-face-username>:<your-hugging-face-token>@huggingface.co/mistralai/Mixtral-8x7B-Instruct-v0.1
   ```

1. Renommez la configuration du jeton :

   ```shell
   cd <path-to-model>/Mixtral-8x7B-Instruct-v0.1
   cp tokenizer.model tokenizer.model.v3
   ```

1. Exécutez le modèle :

   ```shell
   vllm serve <path-to-model>/Mixtral-8x7B-Instruct-v0.1 \
     --tensor_parallel_size 4 \
     --served_model_name <choose-a-name-for-the-model> \
     --tokenizer_mode mistral \
     --load_format safetensors \
     --tokenizer <path-to-model>/Mixtral-8x7B-Instruct-v0.1
   ```

#### Désactiver la journalisation des requêtes pour réduire la latence {#disable-request-logging-to-reduce-latency}

Lorsque vous exécutez vLLM en production, vous pouvez réduire considérablement la latence au moyen de l'option `--disable-log-requests`, qui désactive la journalisation des requêtes.

> [!note]
> Utilisez cette option uniquement lorsque vous n'avez pas besoin d'une journalisation détaillée des requêtes.

Désactiver la journalisation des requêtes réduit au minimum le surcoût dû aux logs détaillés, surtout en cas de forte charge, et peut contribuer à améliorer les performances.

```shell
vllm serve <path-to-model>/<model-version> \
--served_model_name <choose-a-name-for-the-model>  \
--disable-log-requests
```

Les tests de performance internes ont permis d'observer que cette modification améliorait sensiblement les temps de réponse.

## Déploiements de modèles hébergés dans le cloud {#cloud-hosted-model-deployments}

GitLab a validé et testé les fournisseurs suivants. La passerelle d'IA prend en charge les fournisseurs de LLM compatibles avec [LiteLLM](https://docs.litellm.ai/docs/providers).

- [AWS Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html)
- [Amazon Bedrock Mantle](#configure-amazon-bedrock-mantle)
- [Gemini Enterprise Agent Platform](https://cloud.google.com/products/gemini-enterprise-agent-platform)
- [Azure OpenAI](#configure-azure-openai)
- [Anthropic](https://platform.claude.com/docs/en/about-claude/models/overview)
- [OpenAI](https://developers.openai.com/api/docs/models)

### Configurer l'authentification auprès d'AWS Bedrock {#configure-authentication-with-aws-bedrock}

Vous pouvez authentifier votre passerelle d'IA auprès d'AWS Bedrock de plusieurs manières.

Prérequis :

- Les modèles sont automatiquement activés dans Bedrock lors de leur première invocation. Pour plus d'informations, consultez [Accès aux modèles Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html).
- Disposer d'identifiants AWS configurés avec les autorisations IAM appropriées.

#### Configuration recommandée d'Amazon EKS avec un chart Helm {#amazon-eks-with-helm-chart-recommended}

Utilisez IRSA (IAM Roles for Service Accounts) pour que les pods de votre passerelle d'IA s'authentifient auprès d'AWS Bedrock sans stocker d'identifiants statiques.

Après avoir authentifié Amazon EKS avec IRSA, la passerelle d'IA obtient automatiquement des identifiants temporaires à partir du rôle IRSA.

Pour authentifier Amazon EKS au moyen d'IRSA :

1. Créez une politique IAM qui accorde l'accès aux modèles Bedrock. Vous pouvez restreindre la portée de cette politique à des modèles précis si vous avez besoin de renforcer la sécurité :

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel",
           "bedrock:InvokeModelWithResponseStream"
         ],
         "Resource": "arn:aws:bedrock:*::foundation-model/*"
       }
     ]
   }
   ```

   ```shell
   aws iam create-policy \
     --policy-name bedrock-ai-gateway-access \
     --policy-document file://bedrock-policy.json \
     --description "Bedrock access for AI Gateway"
   ```

1. Facultatif. Pour renforcer le contrôle des accès, remplacez la ressource désignée par le caractère générique par le nom de ressource Amazon (ARN) d'un modèle précis. Cela garantit que seuls les modèles approuvés sont accessibles, même si la configuration GitLab change. Pour connaître les ARN de modèles disponibles, consultez [ID de modèles Amazon Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html).

   ```json
   "Resource": [
     "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
     "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
   ]
   ```

   > [!note]
   > Certains modèles peuvent utiliser des formats ARN différents. Par exemple, les modèles plus récents peuvent nécessiter des ARN de profils d'inférence en plus des ARN de modèles de fondation. Pour vérifier le format ARN du modèle concerné, consultez [ID de modèles Amazon Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html).

1. Créez un rôle IAM avec une politique de confiance pour votre compte de service Amazon EKS. Remplacez les valeurs suivantes :

   - `YOUR_ACCOUNT_ID` : Votre ID de compte AWS.
   - `REGION` : La région de votre cluster Amazon EKS (par exemple, `us-east-1`).
   - `YOUR_OIDC_ID` : L'ID du fournisseur OIDC de votre cluster Amazon EKS.
   - `NAMESPACE` : L'espace de nommage Kubernetes dans lequel la passerelle d'IA est déployée.

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/oidc.eks.REGION.amazonaws.com/id/YOUR_OIDC_ID"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "oidc.eks.REGION.amazonaws.com/id/YOUR_OIDC_ID:sub": "system:serviceaccount:NAMESPACE:ai-gateway",
             "oidc.eks.REGION.amazonaws.com/id/YOUR_OIDC_ID:aud": "sts.amazonaws.com"
           }
         }
       }
     ]
   }
   ```

   ```shell
   # Create the role
   aws iam create-role \
     --role-name eks-ai-gateway-bedrock \
     --assume-role-policy-document file://trust-policy.json \
     --description "EKS IRSA role for AI Gateway to access Bedrock"
   ```

1. Associez la politique IAM de Bedrock à ce rôle.

   ```shell
   # Attach the role
   aws iam attach-role-policy \
     --role-name eks-ai-gateway-bedrock \
     --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/bedrock-ai-gateway-access
   ```

1. Pour configurer le chart Helm, installez la passerelle d'IA avec l'annotation du rôle IAM :

   ```yaml
   serviceAccount:
     create: true
     name: ai-gateway
     annotations:
       eks.amazonaws.com/role-arn: arn:aws:iam::YOUR_ACCOUNT_ID:role/YOUR_ROLE_NAME
   extraEnvironmentVariables:
     - name: AWS_REGION
       value: us-east-1
   ```

Pour plus d'informations, consultez [les rôles IAM pour les comptes de service](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html).

#### Déploiements Docker {#docker-deployments}

Configurez les identifiants IAM au moyen de variables d'environnement lorsque vous démarrez le conteneur de la passerelle d'IA :

```shell
docker run -d \
  -e AWS_ACCESS_KEY_ID=your-access-key \
  -e AWS_SECRET_ACCESS_KEY=your-secret-key \
  -e AWS_REGION=us-east-1 \
  -p 5052:5052 \
  registry.gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/model-gateway:self-hosted-vX.Y.Z-ee
```

L'utilisateur ou le rôle IAM doit disposer d'une politique semblable à celle que vous définiriez pour Amazon EKS avec un chart Helm.

#### Déploiements Kubernetes {#kubernetes-deployments}

Pour les clusters Kubernetes autres qu'Amazon EKS, vous pouvez utiliser des secrets Kubernetes pour stocker les identifiants AWS :

1. Créez un secret Kubernetes :

   ```shell
   kubectl create secret generic aws-credentials \
     --from-literal=access-key-id=YOUR_ACCESS_KEY_ID \
     --from-literal=secret-access-key=YOUR_SECRET_ACCESS_KEY \
     -n YOUR_NAMESPACE
   ```

1. Configurez le chart Helm pour référencer le secret :

   ```yaml
   extraEnvironmentVariables:
     - name: AWS_ACCESS_KEY_ID
       valueFrom:
         secretKeyRef:
           name: aws-credentials
           key: access-key-id
     - name: AWS_SECRET_ACCESS_KEY
       valueFrom:
         secretKeyRef:
           name: aws-credentials
           key: secret-access-key
     - name: AWS_REGION
       value: us-east-1
   ```

#### Assumer un rôle IAM avec AWS Bedrock {#assume-an-iam-role-with-aws-bedrock}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259000) dans GitLab 19.5.

{{< /history >}}

Par défaut, la passerelle d'IA appelle Bedrock avec les informations d'identification dont elle dispose déjà (par exemple, le rôle IRSA ou les variables d'environnement). Pour appeler Bedrock avec un rôle différent (par exemple, un rôle dans un autre compte AWS), fournissez un rôle IAM pour chaque modèle auto-hébergé. La passerelle d'IA utilise ses propres informations d'identification pour assumer ce rôle via l'action [`AssumeRole`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) du service AWS Security Token Service (STS). La passerelle d'IA utilise ensuite les informations d'identification temporaires pour appeler Bedrock.

Prérequis :

- Disposer d'un accès administrateur.
- [La passerelle d'IA est authentifiée auprès d'AWS](#configure-authentication-with-aws-bedrock). L'identité AWS sous laquelle s'exécute la passerelle d'IA peut appeler `sts:AssumeRole` sur le rôle.

Pour assumer un rôle IAM lorsque vous appelez Bedrock :

1. Dans le compte AWS cible, créez un rôle IAM avec la politique de relation d'approbation suivante. Remplacez :

   - `AI_GATEWAY_PRINCIPAL_ARN` par l'ARN de l'identité AWS sous laquelle s'exécute la passerelle d'IA (par exemple, le rôle IRSA `arn:aws:iam::AI_GATEWAY_ACCOUNT_ID:role/eks-ai-gateway-bedrock`).
   - `GITLAB_INSTANCE_ID` par l'identifiant de votre instance GitLab tel qu'il apparaît dans la zone de texte **Rôle IAM à assumer**.

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "AI_GATEWAY_PRINCIPAL_ARN"
         },
         "Action": "sts:AssumeRole",
         "Condition": {
           "StringEquals": {
             "sts:ExternalId": "GITLAB_INSTANCE_ID"
           }
         }
       }
     ]
   }
   ```

   La passerelle d'IA envoie l'identifiant d'instance en tant qu'ID externe STS lorsqu'elle assume le rôle. La condition empêche un autre client de la passerelle d'IA qui connaît l'ARN du rôle d'utiliser l'identité de la passerelle d'IA pour assumer votre rôle (le problème du député confus). L'identifiant d'instance n'est pas un secret.

1. Pour invoquer des modèles Bedrock, attachez une politique d'autorisation au rôle. Vous pouvez restreindre la portée de `Resource` à des modèles spécifiques :

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel",
           "bedrock:InvokeModelWithResponseStream"
         ],
         "Resource": "arn:aws:bedrock:*::foundation-model/*"
       }
     ]
   }
   ```

1. Si la passerelle d'IA s'exécute dans un compte différent de celui du rôle, autorisez également l'identité de la passerelle d'IA à appeler `sts:AssumeRole` sur le rôle avec une politique basée sur l'identité :

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "sts:AssumeRole",
         "Resource": "arn:aws:iam::ROLE_ACCOUNT_ID:role/YOUR_ROLE_NAME"
       }
     ]
   }
   ```

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sélectionnez **Configurer les modèles pour GitLab Duo**.
1. Pour la plateforme **Amazon Bedrock**, ajoutez ou modifiez un modèle auto-hébergé.
1. Facultatif. Dans la zone de texte **Rôle IAM à assumer**, saisissez l'ARN du rôle (par exemple, `arn:aws:iam::123456789012:role/YOUR_ROLE_NAME`). Si vous laissez ce champ vide, la passerelle d'IA utilise ses propres informations d'identification.
1. Facultatif. Sélectionnez **Connexion au test**.
1. Sélectionnez **Ajouter un modèle auto-hébergé**.

Un rôle IAM et une clé d'API (jeton porteur) sont mutuellement exclusifs. GitLab n'accepte pas de rôle IAM pour un modèle disposant d'une clé d'API, et la passerelle d'IA rejette toute requête contenant les deux.

> [!note]
> Pour envoyer l'ID externe STS, la version de la passerelle d'IA doit inclure la [prise en charge de `AssumeRole` pour les modèles Amazon Bedrock](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/merge_requests/7210). Avec une version antérieure de la passerelle d'IA, celle-ci n'envoie pas l'ID externe STS, et l'hypothèse de rôle échoue si la politique d'approbation requiert `sts:ExternalId`.

#### Clés API AWS Bedrock {#aws-bedrock-api-keys}

Pour utiliser les clés API AWS Bedrock comme alternative aux identifiants IAM :

1. [Créer une clé API Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-generate.html)
1. Créez un secret Kubernetes avec la clé API :

   ```shell
   kubectl create secret generic bedrock-api-key \
     --from-literal=token=YOUR_BEDROCK_API_KEY \
     -n YOUR_NAMESPACE
   ```

1. Pour configurer la passerelle d'IA, ajoutez les éléments suivants à votre `values.yaml` :

   ```yaml
   extraEnvironmentVariables:
     - name: AWS_BEARER_TOKEN_BEDROCK
       valueFrom:
         secretKeyRef:
           name: bedrock-api-key
           key: token
     - name: AWS_REGION
       value: us-east-1
   ```

#### Points de terminaison VPC privés {#private-vpc-endpoints}

Pour utiliser un point de terminaison Bedrock privé dans un VPC, définissez la variable d'environnement `AWS_BEDROCK_RUNTIME_ENDPOINT`.

Pour les déploiements Helm :

```yaml
extraEnvironmentVariables:
  - name: AWS_BEDROCK_RUNTIME_ENDPOINT
    value: https://bedrock-runtime.us-east-1.amazonaws.com
```

Pour les déploiements Docker :

```shell
docker run -d \
  -e AWS_BEDROCK_RUNTIME_ENDPOINT=https://bedrock-runtime.us-east-1.amazonaws.com \
  -e AWS_REGION=us-east-1 \
  # ... other configuration
```

Pour les points de terminaison VPC, utilisez le format : `https://vpce-{vpc-endpoint-id}-{service-name}.{region}.vpce.amazonaws.com`

#### Garde-fous Bedrock {#bedrock-guardrails}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/merge_requests/4715) dans GitLab 19.0.

{{< /history >}}

Vous pouvez utiliser Amazon Bedrock Guardrails pour appliquer des contrôles de sécurité et de confidentialité aux requêtes que vous adressez aux modèles Bedrock.

Pour appliquer ces garde-fous, attribuez à la variable d'environnement `AIGW_BEDROCK_GUARDRAIL_CONFIG` un objet JSON contenant les champs suivants :

| Champ                 | Description |
|-----------------------|-------------|
| `guardrailIdentifier` | L'ID du garde-fou dans votre compte AWS. Peut être un ID simple (`abc123`) ou un ARN complet (`arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123`). |
| `guardrailVersion`    | La version du garde-fou à appliquer. Attribuez-lui la valeur `1`. |
| `trace`               | Indique si les informations de trace doivent être incluses dans la réponse. Peut prendre la valeur `enabled` ou `disabled`. |

> [!note]
> Lorsqu'un garde-fou bloque une requête, le message renvoyé aux utilisateurs est le message de blocage personnalisé configuré dans votre garde-fou AWS Bedrock, et non un message fourni par GitLab. Configurez les messages de blocage de votre garde-fou dans la console AWS pour garantir que les utilisateurs reçoivent des indications adaptées.

Pour un déploiement Helm, définissez la variable d'environnement comme suit :

```yaml
extraEnvironmentVariables:
  - name: AIGW_BEDROCK_GUARDRAIL_CONFIG
    value: '{"guardrailIdentifier": "<guardrail_id>", "guardrailVersion": "1", "trace": "disabled"}'
```

Pour un déploiement Docker :

```shell
docker run -d \
  -e AIGW_BEDROCK_GUARDRAIL_CONFIG='{"guardrailIdentifier": "<guardrail_id>", "guardrailVersion": "1", "trace": "disabled"}' \
  # ... other configuration
```

Pour plus d'informations, consultez [Amazon Bedrock Guardrails](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html).

### Configurer Amazon Bedrock Mantle {#configure-amazon-bedrock-mantle}

{{< details >}}

- Statut : version bêta

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/22787) en [version bêta](../../policy/development_stages_support.md#beta) dans GitLab 19.3.
- Les modèles GPT-5 et ultérieurs ont été [ajoutés](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/merge_requests/6956) en tant que modèles pris en charge le 16 septembre 2026.

{{< /history >}}

[Amazon Bedrock Mantle](https://docs.aws.amazon.com/bedrock/latest/userguide/bedrock-mantle.html) est un service d'inférence compatible avec l'API OpenAI, proposé par AWS. Configurez Amazon Bedrock Mantle au moyen de la plateforme API, comme pour les autres points de terminaison compatibles avec l'API OpenAI.

Les modèles suivants sont validés et pris en charge sur Amazon Bedrock Mantle :

| Modèle | Identifiant du modèle |
|-------|------------------|
| GPT-5.4 | `bedrock_mantle/openai.gpt-5.4` |
| GPT-5.5 | `bedrock_mantle/openai.gpt-5.5` |
| GPT-5.6 Luna | `bedrock_mantle/openai.gpt-5.6-luna` |
| GPT-5.6 Sol | `bedrock_mantle/openai.gpt-5.6-sol` |
| GPT-5.6 Terra | `bedrock_mantle/openai.gpt-5.6-terra` |
| GPT-6 Astra | `bedrock_mantle/openai.gpt-6-astra` |
| GPT-6 Luna | `bedrock_mantle/openai.gpt-6-luna` |
| GPT-6 Sol | `bedrock_mantle/openai.gpt-6-sol` |
| GPT-6.1 Sol | `bedrock_mantle/openai.gpt-6.1-sol` |
| GPT OSS 120B | `bedrock_mantle/openai.gpt-oss-120b` |

La passerelle d'IA envoie les requêtes pour les modèles GPT-5 et ultérieurs à l'API Responses d'Amazon Bedrock Mantle. Utilisez le même préfixe `bedrock_mantle/` pour tous les modèles.

Les modèles Anthropic ne sont pas pris en charge sur Amazon Bedrock Mantle. Amazon Bedrock Mantle sert ces modèles uniquement via l'API Anthropic Messages, et la passerelle d'IA n'utilise pas cette API pour cette plateforme. Pour utiliser des modèles Anthropic sur AWS, [ajoutez plutôt un modèle Amazon Bedrock](configure_duo_features.md#add-an-amazon-bedrock-model).

Pour configurer un modèle Amazon Bedrock Mantle, [ajoutez un modèle auto-hébergé](configure_duo_features.md#add-a-self-hosted-model) avec les valeurs suivantes :

- Pour **Famille de modèles**, sélectionnez la famille correspondant au modèle. Pour les modèles OpenAI, sélectionnez **GPT**.
- Pour **Point de terminaison**, saisissez le point de terminaison régional sous la forme `https://bedrock-mantle.<region>.api.aws/v1` (par exemple, `https://bedrock-mantle.us-east-1.api.aws/v1`).
- Pour **Identifiant du modèle**, utilisez le préfixe `bedrock_mantle/` (par exemple, `bedrock_mantle/openai.gpt-oss-120b`).
- Pour **Clé de l'API**, saisissez une clé d'API Amazon Bedrock Mantle. Pour plus d'informations, consultez [Clés API AWS Bedrock](#aws-bedrock-api-keys).

### Configurer Azure OpenAI {#configure-azure-openai}

[Azure OpenAI](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure?tabs=global-standard&pivots=azure-openai) sert les modèles via l'API Chat Completions et l'[API Responses](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/responses). La plupart des modèles prennent en charge l'API Chat Completions. Certains modèles plus récents sont disponibles uniquement via l'API Responses.

Pour configurer un modèle Azure OpenAI, [ajoutez un modèle auto-hébergé](configure_duo_features.md#add-a-self-hosted-model) avec les valeurs suivantes :

- Pour **Famille de modèles**, sélectionnez la famille correspondant au modèle. Pour GPT-5, sélectionnez **GPT**.
- Pour **Point de terminaison**, saisissez le point de terminaison de votre ressource Azure OpenAI au format `https://<resource-name>.openai.azure.com`. N'ajoutez pas de chemin ni de version d'API.
- Pour **Identifiant du modèle**, utilisez le préfixe `azure/` suivi du nom de votre déploiement (par exemple, `azure/gpt-4o`). Cet identifiant envoie les requêtes à l'API Chat Completions. Pour envoyer des requêtes à l'API Responses à la place, consultez [Utiliser l'API Responses](#use-the-responses-api).
- Pour **Clé de l'API**, saisissez une clé d'API pour votre ressource Azure OpenAI.

#### Utiliser l'API Responses {#use-the-responses-api}

Pour un déploiement disponible uniquement via l'API Responses, utilisez le préfixe `azure/responses/`. Pour **Identifiant du modèle**, saisissez le préfixe suivi du nom de votre déploiement (par exemple, `azure/responses/gpt-5`).

La passerelle d'IA envoie les requêtes vers le chemin `/openai/responses` de votre ressource. La passerelle d'IA convertit chaque requête au format de l'API Responses et reconvertit la réponse. La conversion prend en charge les réponses en flux et les appels d'outils. Vous n'avez pas besoin d'un proxy pour assurer la traduction entre les deux API.

### Configurer l'authentification auprès de Gemini Enterprise Agent Platform {#configure-authentication-with-gemini-enterprise-agent-platform}

Pour utiliser des modèles de Gemini Enterprise Agent Platform, vous devez authentifier votre instance de passerelle d'IA. Vous pouvez utiliser l'un des mécanismes suivants :

- Exportez les variables d'environnement lors du démarrage du conteneur Docker. Pour ce faire, définissez les variables d'environnement suivantes lorsque vous lancez le conteneur de la passerelle d'IA :

  ```shell
  GOOGLE_APPLICATION_CREDENTIALS=/path/to/application_default_credentials.json
  VERTEXAI_PROJECT=<gcp-project-id>
  VERTEXAI_LOCATION=global # or any specific location, e.g., "europe-west1"
  ```

- Exécutez le conteneur de la passerelle d'IA sur Google Cloud Run et utilisez le [compte de service Cloud Run](https://docs.litellm.ai/docs/providers/vertex#using-gcp-service-account) pour accéder à Gemini Enterprise Agent Platform.

## Sujets connexes {#related-topics}

- [Documentation sur les modèles pris en charge et les exigences matérielles](supported_models_and_hardware_requirements.md).
- [Modèles de fondation pris en charge par Amazon Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html)
- [Bonnes pratiques AWS IAM](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Sécurité Amazon Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- Pour obtenir des informations sur la configuration, consultez la documentation suivante :
  - [Présentation de l'API Anthropic](https://platform.claude.com/docs/en/api/overview)
  - [Présentation de l'API OpenAI](https://developers.openai.com/api/docs)
  - [Utiliser des modèles Azure OpenAI](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/working-with-models?tabs=powershell)
