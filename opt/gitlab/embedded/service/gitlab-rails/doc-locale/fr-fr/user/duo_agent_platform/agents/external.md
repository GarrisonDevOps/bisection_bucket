---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Agents externes
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="Informations sur le modèle" >}}

- Non disponible sur GitLab Duo avec des modèles auto-hébergés

{{< /collapsible >}}

{{< history >}}

- Introduit sur GitLab.com dans GitLab 18.3 [avec un feature flag](../../../administration/feature_flags/_index.md) nommé `ai_flow_triggers`. Activés par défaut.
- Renommé depuis les agents CLI dans GitLab 18.6
- Claude Code Agent et Codex Agent activés sur GitLab Self-Managed et GitLab Dedicated dans GitLab 18.6.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/578318) de l'activation dans les groupes dans GitLab 18.7 [avec le feature flag](../../../administration/feature_flags/_index.md) `ai_catalog_agents`. Activé sur GitLab.com.
- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/20743) de l'activation directement dans les projets en tant que chargé de maintenance dans GitLab 18.10 [avec le feature flag](../../../administration/feature_flags/_index.md) `ai_catalog_project_level_enablement`. Activé par défaut sur GitLab.com, GitLab Self-Managed et GitLab Dedicated.
- Suppression du feature flag `ai_catalog_project_level_enablement` dans GitLab 18.11.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/592454) du type d'événement de déclencheur **Requête de fusion prête** dans GitLab 19.0 avec le [feature flag](../../../administration/feature_flags/_index.md) `merge_request_ready_flow_trigger`. Désactivé par défaut.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/592455) du type d'événement de déclencheur **Conflit de code dans une merge request** dans GitLab 19.1.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/237081) du type d'événement de déclencheur **Requête de fusion** avec l'action **Approuvé** dans GitLab 19.1.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/599985) du type d'événement de déclencheur **Élément de travail créé** dans GitLab 19.1.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/598421) du type d'événement de déclencheur **Requête de fusion prête** dans GitLab 19.1. Suppression du feature flag `merge_request_ready_flow_trigger`.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/599983) du type d'événement de déclencheur **Statut de l'élément de travail modifié** dans GitLab 19.2.
- Type d'événement déclencheur **Requête de fusion** avec l'action **Créés** [introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/242698) dans GitLab 19.4.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag et activée pour les clients vérifiés. Pour activer les agents externes pour votre espace de nommage client ou votre instance GitLab, contactez le support GitLab.

Les agents GitLab Duo fonctionnent en parallèle pour vous aider à créer du code, rechercher des résultats et effectuer des tâches simultanément.

Vous pouvez créer un agent et l'intégrer à un fournisseur de modèle d'IA externe pour le personnaliser selon les besoins de votre organisation. Ensuite, dans un ticket, un epic ou une merge request d'un projet, vous pouvez mentionner cet agent externe dans un commentaire ou une discussion et demander à l'agent d'effectuer une tâche.

L'agent externe :

- Lit et analyse le contexte environnant et le code du dépôt.
- Détermine l'action appropriée à entreprendre, tout en respectant les permissions du projet et en conservant une piste d'audit.
- Exécute un pipeline CI/CD et répond dans GitLab avec soit une modification prête à fusionner, soit un commentaire en ligne.

## Prérequis {#prerequisites}

- Satisfaire aux [prérequis pour GitLab Duo Agent Platform](../_index.md#prerequisites).
- Avoir [l'exécution des flows activée](../flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).
- Avoir [les agents externes activés](#turn-external-agents-on-or-off).

## Considérations relatives à la sécurité {#security-considerations}

Les agents externes s'intègrent à des fournisseurs de modèles d'IA tiers et présentent des caractéristiques de sécurité différentes de celles des agents et flows intégrés à GitLab. En utilisant des agents externes, vous acceptez les risques suivants :

- **Vulnérabilités d'injection de prompt** : GitLab met en œuvre une analyse de prompt tiers pour réduire le risque d'injections de prompt. Cette analyse n'est pas disponible pour les agents externes.
- **Dépendance à un fournisseur tiers** : le fournisseur de modèle d'IA externe gère tous les contrôles de sécurité (y compris l'analyse de prompt, la surveillance et les alertes), et non GitLab.
- **Accès réseau** : les agents externes effectuent des appels réseau vers des fournisseurs d'IA tiers. Les données envoyées à ces fournisseurs sont soumises à leurs politiques de sécurité et pratiques de gestion des données.
- **Isolation limitée** : les agents externes ne bénéficient pas du même niveau d'isolation réseau et de restrictions de sécurité que ceux appliqués aux agents et flows natifs de GitLab.

Avant d'activer des agents externes dans votre organisation, examinez vos exigences de sécurité et la documentation de sécurité fournie par le fournisseur de modèle d'IA que vous avez choisi.

Pour une vue d'ensemble plus large des menaces de sécurité et des mesures d'atténuation dans la plateforme Duo Agent, consultez la [documentation sur les menaces de sécurité de la plateforme Duo Agent](../security_threats.md).

## Démarrage rapide pour les agents externes gérés par GitLab {#quickstart-for-gitlab-managed-external-agents}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate

{{< /details >}}

{{< history >}}

- Introduit dans GitLab 18.8 sur GitLab.com.

{{< /history >}}

Les intégrations suivantes ont été testées par GitLab et sont disponibles :

- [Claude Code](https://code.claude.com/docs/en/overview)
- [OpenAI Codex](https://help.openai.com/en/articles/11096431-openai-codex-cli-getting-started)
- [Amazon Q](https://aws.amazon.com/q/)
- [Gemini](https://gemini.google.com/)

Avant de pouvoir créer un agent et l'intégrer à un fournisseur de modèle d'IA externe, vous devez satisfaire aux [prérequis de la plateforme GitLab Duo Agent](../_index.md#prerequisites).

Les agents externes gérés peuvent utiliser des identifiants gérés par GitLab et peuvent être activés dans des groupes sans configuration supplémentaire de l'agent.

Étapes requises pour activer et utiliser des agents gérés :

1. Accédez à l'agent dans le catalogue d'IA. Recherchez le nom de l'agent ou utilisez l'URL directe.

   Les agents externes gérés par GitLab affichent un badge maintenu par GitLab ({{< icon name="tanuki-verified" >}}).

1. [Activez l'agent](#enable-the-agent).
1. [Utilisez l'agent externe](#use-an-external-agent) dans des tickets, des epics ou des merge requests.

### Claude Code Agent {#claude-code-agent}

L'[agent Claude Code de GitLab](https://gitlab.com/explore/ai-catalog/agents/2337/) utilise des identifiants gérés par GitLab et ne nécessite pas de configuration supplémentaire.

### Codex Agent {#codex-agent}

L'[agent Codex de GitLab](https://gitlab.com/explore/ai-catalog/agents/2334/) utilise des identifiants gérés par GitLab et ne nécessite pas de configuration supplémentaire.

### Amazon Q Developer Agent {#amazon-q-developer-agent}

{{< details >}}

- Offre : GitLab.com

{{< /details >}}

L'[agent Amazon Q Developer](https://gitlab.com/explore/ai-catalog/agents/2332/) n'utilise pas les identifiants gérés par GitLab. Pour utiliser cet agent, vous devez fournir vos propres identifiants.

Pour utiliser l'agent Amazon Q Developer :

- Ajoutez les variables d'environnement suivantes aux paramètres CI/CD de votre projet :

  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - `AWS_REGION_NAME`
  - `AMAZON_Q_SIGV4`

### Develop with Gemini Agent {#develop-with-gemini-agent}

{{< details >}}

- Offre : GitLab.com

{{< /details >}}

L'[agent Develop with Gemini](https://gitlab.com/explore/ai-catalog/agents/2331/) n'utilise pas les identifiants gérés par GitLab. Pour utiliser cet agent, vous devez fournir vos propres identifiants.

Pour utiliser l'agent Develop with Gemini :

- Ajoutez les variables d'environnement suivantes aux paramètres CI/CD de votre projet :

  - `GOOGLE_CREDENTIALS` - Ajoutez l'emplacement du fichier JSON des identifiants Google. Pour plus d'informations, consultez la [variable d'environnement `GOOGLE_APPLICATION_CREDENTIALS`](https://docs.cloud.google.com/docs/authentication/application-default-credentials#GAC).
  - `GOOGLE_CLOUD_PROJECT`
  - `GOOGLE_CLOUD_LOCATION`

### Ajouter des agents gérés par GitLab à d'autres instances {#add-gitlab-managed-agents-to-other-instances}

{{< details >}}

- Offre : GitLab Self-Managed, GitLab Dedicated
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221986) en version expérimentale dans GitLab 18.8.

{{< /history >}}

Les administrateurs peuvent ajouter l'agent Claude et l'agent Codex à leurs instances GitLab.

Prérequis :

- Vous devez être administrateur.

Pour ajouter des agents externes à votre instance :

{{< tabs >}}

{{< tab title="Interface utilisateur GitLab" >}}

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sous **Agents externes gérés par GitLab**, sélectionnez **Ajouter au Catalogue IA**.

{{< /tab >}}

{{< tab title="Tâche Rake" >}}

Pour le package Linux (Omnibus) :

```shell
sudo gitlab-rake gitlab:ai_catalog:seed_external_agents
```

Pour une installation compilée depuis les sources :

```shell
bundle exec rake gitlab:ai_catalog:seed_external_agents
```

{{< /tab >}}

{{< /tabs >}}

Vous pouvez également ajouter des agents externes avec l'[API](../../../api/admin/ai_catalog.md).

### Identifiants d'accès {#access-credentials}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/567791) dans GitLab 18.4.

{{< /history >}}

Les agents externes utilisent des identifiants gérés par GitLab via une passerelle d'IA.

Lorsque vous utilisez des identifiants gérés par GitLab :

- Définissez `injectGatewayToken: true` dans la configuration de votre agent externe.
- Configurez l'agent externe pour utiliser les points de terminaison proxy de la passerelle d'IA GitLab.

Les variables d'environnement suivantes sont automatiquement injectées lorsque `injectGatewayToken` est `true` :

- `AI_FLOW_AI_GATEWAY_TOKEN` : le jeton d'authentification pour la passerelle d'IA
- `AI_FLOW_AI_GATEWAY_HEADERS` : en-têtes formatés pour les requêtes API

Les identifiants gérés par GitLab sont disponibles uniquement pour Anthropic Claude et OpenAI Codex.

Pour authentifier un agent auprès de l'API GitLab, consultez [S'authentifier auprès de l'API GitLab](#authenticate-to-the-gitlab-api).

### Modèles pris en charge {#supported-models}

Pour les identifiants gérés par GitLab, les modèles d'IA suivants sont pris en charge :

Anthropic Claude :

- `claude-haiku-4-5-20251001`
- `claude-opus-4-5-20251101`
- `claude-opus-4-6`
- `claude-sonnet-4-20250514`
- `claude-sonnet-4-5-20250929`
- `claude-sonnet-4-6`

OpenAI Codex :

- `gpt-5`
- `gpt-5-mini-2025-08-07`
- `gpt-5.1`
- `gpt-5.1-2025-11-13`
- `gpt-5.2-2025-12-11`
- `gpt-5.3-codex`
- `gpt-5.4-2026-03-05`
- `gpt-5.4-mini`
- `gpt-5.4-nano`

## Configurer les variables CI/CD {#configure-cicd-variables}

Ajoutez des variables à votre projet pour déterminer comment GitLab se connecte au fournisseur tiers.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour ajouter ou mettre à jour une variable dans les paramètres du projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD**.
1. Développez **Variables**.
1. Sélectionnez **Ajouter une variable** et renseignez les champs :
   - **Type** : sélectionnez **Variable (par défaut)**.
   - **Environnements** : sélectionnez **Tous (par défaut)**.
   - **Visibilité** : sélectionnez la visibilité souhaitée.

     Pour les variables de clé API et de jeton d'accès personnel, sélectionnez **Masquée** ou **Masquée et cachée**.
   - Décochez la case **Protéger la variable**.
   - Décochez la case **Développer la référence de la variable**.
   - **Description (facultatif)** : saisissez une description de la variable.
   - **Clé** : saisissez le nom de la variable d'environnement de la variable CI/CD (par exemple, `GITLAB_HOST`).
   - **Valeur** : la valeur de la clé API, du jeton d'accès personnel ou de l'hôte.
1. Sélectionnez **Ajouter une variable**.

Pour plus d'informations, consultez comment [ajouter des variables CI/CD aux paramètres d'un projet](../../../ci/variables/_index.md#define-a-cicd-variable-in-the-ui).

### Variables CI/CD pour les agents externes {#cicd-variables-for-external-agents}

Les variables CI/CD suivantes sont disponibles :

| Intégration                | Variable d'environnement         | Description |
|----------------------------|------------------------------|-------------|
| Tous                        | `GITLAB_TOKEN_<integration>` | Jeton d'accès personnel pour l'utilisateur du compte de service. |
| Tous                        | `GITLAB_HOST`                | Nom d'hôte de l'instance GitLab (par exemple, `gitlab.com`). |
| Tous                        | `ADDITIONAL_INSTRUCTIONS`    | Instructions supplémentaires que l'agent inclut dans les prompts. |
| Amazon Q                   | `AWS_SECRET_NAME`            | Nom du secret AWS Secret Manager. |
| Amazon Q                   | `AWS_REGION_NAME`            | Nom de la région AWS. |
| Amazon Q                   | `AMAZON_Q_SIGV4`             | Identifiants Amazon Q Sig V4. |
| Google Gemini CLI          | `GOOGLE_CREDENTIALS`         | Contenu du fichier d'identifiants JSON. |
| Google Gemini CLI          | `GOOGLE_CLOUD_PROJECT`       | ID du projet Google Cloud. |
| Google Gemini CLI          | `GOOGLE_CLOUD_LOCATION`      | Emplacement du projet Google Cloud. |

## S'authentifier auprès de l'API GitLab {#authenticate-to-the-gitlab-api}

Chaque agent externe reçoit un jeton OAuth GitLab défini comme variable d'environnement `AI_FLOW_GITLAB_TOKEN`. Ces jetons sont limités à la portée qui leur est accordée. Ils peuvent uniquement accéder aux [points de terminaison de l'API GitLab avec la portée `ai_workflows`](../flows/foundational_flows/software_development.md#apis-that-the-flow-has-access-to). Les points de terminaison en dehors de cette portée sont refusés même lorsque le jeton est envoyé correctement.

Pour appeler l'API GitLab depuis un agent externe, envoyez `AI_FLOW_GITLAB_TOKEN` en tant que jeton `Authorization: Bearer`. Si vous utilisez l'en-tête `PRIVATE-TOKEN` pour envoyer le jeton, l'API retourne `401 Unauthorized`.

```shell
curl --header "Authorization: Bearer $AI_FLOW_GITLAB_TOKEN" \
  "https://$AI_FLOW_GITLAB_HOSTNAME/api/v4/user"
```

Pour utiliser la CLI `glab` dans votre agent, écrivez le jeton dans `~/.config/glab-cli/config.yml` et définissez `is_oauth2: "true"` afin que `glab` envoie le jeton correctement :

```yaml
hosts:
  $AI_FLOW_GITLAB_HOSTNAME:
    token: $AI_FLOW_GITLAB_TOKEN
    is_oauth2: "true"
```

Les agents Claude et Codex gérés par GitLab utilisent ce même modèle. Pour des exemples fonctionnels, consultez les [exemples de configuration d'agent externe](external_examples.md).

## S'authentifier avec des jetons d'identité {#authenticate-with-id-tokens}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224940) dans GitLab 19.2.

{{< /history >}}

Pour authentifier un agent externe personnalisé auprès de services tiers OpenID Connect (OIDC), déclarez des [jetons d'identité](../../../ci/secrets/id_token_authentication.md) dans la configuration de l'agent. GitLab CI/CD génère un jeton web JSON (JWT) signé et l'injecte dans le job de l'agent.

Utilisez des jetons d'identité pour vous authentifier sans stocker d'identifiants à longue durée de vie. Par exemple, vous pouvez récupérer des secrets depuis un gestionnaire de secrets ou signer des artefacts.

Pour configurer les jetons d'identité, ajoutez un bloc `id_tokens` à la configuration de l'agent externe. Chaque jeton nécessite une revendication `aud` (audience) :

```yaml
injectGatewayToken: true
image: node:22-slim
commands:
  - my-authentication-script.sh "$VAULT_ID_TOKEN"
id_tokens:
  VAULT_ID_TOKEN:
    aud: https://vault.example.com
```

La valeur `aud` peut être une chaîne unique ou une liste de chaînes. Chaque jeton est disponible dans le job de l'agent en tant que variable d'environnement portant le nom du jeton.

> [!warning]
> Un jeton d'identification est un identifiant qui accorde l'accès à tout service qui approuve sa revendication `aud`. Définissez la valeur `aud` la plus restrictive possible pour chaque jeton.

Pour plus d'informations sur la charge utile du jeton, consultez [Authentification OpenID Connect (OIDC) à l'aide de jetons d'identité](../../../ci/secrets/id_token_authentication.md).

## Activer l'agent {#enable-the-agent}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/600526) de l'activation d'un agent public pour plusieurs projets dans GitLab 19.2 [avec le feature flag](../../../administration/feature_flags/_index.md) `ai_catalog_bulk_item_consumer_create`. Activés par défaut.
- Feature flag `ai_catalog_bulk_item_consumer_create` supprimé dans GitLab 19.4.

{{< /history >}}

Activez un agent pour le déclencher depuis un ticket, une merge request ou une discussion.

Lorsque vous activez un agent dans un projet, il est simultanément activé dans le groupe principal de ce projet.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

{{< tabs >}}

{{< tab title="Depuis le projet de gestion" >}}

Pour activer un agent externe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **IA** > **Agents**.
1. Sélectionnez l'onglet **Gérés**, puis sélectionnez l'agent que vous souhaitez activer.
1. Dans le coin supérieur droit, sélectionnez **Activer**.
1. Sous **Projet**, sélectionnez le projet dans lequel vous souhaitez activer l'agent.
1. Pour **Ajouter des déclencheurs**, sélectionnez :
   - Un ou plusieurs [types d'événements déclencheurs](../triggers/_index.md#trigger-event-types).
   - Si nécessaire pour le type d'événement déclencheur, une action d'événement déclencheur.
1. Sélectionnez **Activer**.

{{< /tab >}}

{{< tab title="Depuis le catalogue d'IA" >}}

Pour activer un agent externe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** > **Explorer**.
1. Sélectionnez **Catalogue d'IA**, puis sélectionnez l'onglet **Agents**.
1. Sélectionnez l'agent que vous souhaitez activer.
1. Dans le coin supérieur droit, sélectionnez **Activer**.
1. Sous **Projet**, sélectionnez le projet dans lequel vous souhaitez activer l'agent.

   Pour activer un agent public ou restreint pour plusieurs projets, dans la liste déroulante **Projet**, sélectionnez les projets concernés. Vous pouvez sélectionner jusqu'à 100 projets.

1. Pour **Ajouter des déclencheurs**, sélectionnez :
   - Un ou plusieurs [types d'événements déclencheurs](../triggers/_index.md#trigger-event-types).
   - Si nécessaire pour le type d'événement déclencheur, une action d'événement déclencheur.
1. Sélectionnez **Activer**.

{{< /tab >}}

{{< /tabs >}}

L'agent externe apparaît dans les pages **IA** > **Agents** du groupe et du projet. Les membres de tout projet du groupe principal peuvent désormais activer l'agent dans leur projet.

Un compte de service est créé dans le groupe. Le nom du compte suit cette convention de nommage : `ai-<agent>-<group>`.

## Activer dans un projet {#enable-in-a-project}

Si un agent externe est déjà activé dans un groupe principal, vous pouvez l'activer dans les projets de ce groupe.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- L'agent doit être activé dans le groupe principal du projet.

Pour activer un agent externe dans un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **IA** > **Agents**.
1. Dans le coin supérieur droit, sélectionnez **Activer l'agent à partir du groupe**.
1. Dans la liste déroulante, sélectionnez l'agent externe que vous souhaitez activer.
1. Pour **Ajouter des déclencheurs**, sélectionnez :
   - Un ou plusieurs [types d'événements déclencheurs](../triggers/_index.md#trigger-event-types).
   - Si nécessaire pour le type d'événement déclencheur, une action d'événement déclencheur.
1. Sélectionnez **Activer**.

L'agent externe apparaît dans la liste **IA** > **Agents** du projet.

Le compte de service du groupe principal est ajouté au projet. Ce compte se voit attribuer le rôle Développeur.

## Utiliser un agent externe {#use-an-external-agent}

Prérequis :

- Vous devez disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.
- Pour les agents externes gérés par GitLab et les agents externes personnalisés créés dans le catalogue d'IA, l'agent externe doit être activé dans votre projet.
- Pour autoriser l'agent à pousser vers des branches créées par l'agent (branches commençant par ^duo/(fix\|feature\|refactor\|docs/).\*\`), vous devrez peut-être créer des [règles de branche](../../project/repository/branches/branch_rules.md).

1. Dans votre projet, ouvrez un ticket, une merge request ou un epic.
1. Mentionnez, assignez ou demandez une relecture au compte de service. Par exemple :

   ```plaintext
   @service-account-username Can you help analyze this code change?
   ```

1. Une fois que l'agent externe a terminé la tâche, vous voyez une confirmation, ainsi qu'une modification prête à fusionner ou un commentaire en ligne.

## Créer un agent externe personnalisé {#create-a-custom-external-agent}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/207610) dans GitLab 18.6 avec un flag nommé `ai_catalog_third_party_flows`. Activé sur GitLab.com.
- [Activé sur GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/218840) dans GitLab 18.8.
- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/217634) dans GitLab 18.8 avec obligation d'utiliser un [feature flag](../../../administration/feature_flags/_index.md) supplémentaire nommé `ai_catalog_create_third_party_flows`. Désactivé par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique.

Sur GitLab Self-Managed, si le feature flag `ai_catalog_create_third_party_flows` est activé, vous pouvez créer un agent externe avec le catalogue d'IA et le configurer pour qu'il s'exécute dans votre environnement.

Sur GitLab.com, vous ne pouvez pas créer d'agents externes personnalisés. Utilisez plutôt un [agent externe géré par GitLab](#quickstart-for-gitlab-managed-external-agents).

Le workflow recommandé est le suivant :

1. Créez l'agent dans le catalogue d'IA.
1. Activez l'agent pour votre projet et spécifiez un déclencheur qui détermine comment vous appelez l'agent.

Dans ce cas, un compte de service est créé pour vous. Lorsque l'agent s'exécute, il utilise une combinaison des appartenances de l'utilisateur et des appartenances du compte de service. Cette combinaison est appelée [identité composite](../composite_identity.md).

Si vous préférez, vous pouvez [créer un agent externe manuellement](#create-an-external-agent-manually).

### Visibilité des agents {#agent-visibility}

{{< history >}}

- [Extension](https://gitlab.com/gitlab-org/gitlab/-/work_items/582507) des rôles pouvant consulter les agents privés dans GitLab 18.7.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/603253) de la visibilité restreinte dans GitLab 19.3 [avec le feature flag](../../../administration/feature_flags/_index.md) `ai_catalog_internal_visibility`. Activés par défaut.
- Généralement disponible dans GitLab 19.4. Suppression du feature flag `ai_catalog_internal_visibility`.

{{< /history >}}

Lorsque vous créez un agent externe personnalisé, vous sélectionnez un projet pour le gérer et choisissez si l'agent est public, privé ou restreint.

Agents publics :

- Peuvent être consultés par n'importe qui et peuvent être activés dans tout projet répondant aux prérequis.

Agents restreints :

- Peuvent être consultés et utilisés par les membres de tout projet du groupe principal auquel appartient le projet de gestion.
- Peuvent être activés dans d'autres projets du même groupe principal.
- Ne peuvent pas être consultés ni activés en dehors de ce groupe principal.
- Ne peuvent pas être consultés dans le catalogue d'IA sous Explorer.
- Ne peuvent être créés que depuis un projet, et non depuis le catalogue d'IA sous Explorer.

Vous ne pouvez pas faire passer un agent public à une visibilité restreinte si l'agent a été activé par un projet extérieur à ce groupe principal.

Agents privés :

- Ne peuvent être consultés que par les membres du projet de gestion disposant du rôle Invité, Planificateur, Rapporteur, Développeur, Chargé de maintenance ou Propriétaire.
- Ne peuvent pas être activés dans des projets autres que le projet de gestion.

Vous ne pouvez pas faire passer un agent public ou restreint à une visibilité privée si l'agent a été activé par un projet autre que le projet de gestion.

### Créer l'agent dans le catalogue d'IA {#create-the-agent-in-the-ai-catalog}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/603253) de la visibilité restreinte dans GitLab 19.3 [avec le feature flag](../../../administration/feature_flags/_index.md) `ai_catalog_internal_visibility`. Activés par défaut.
- Généralement disponible dans GitLab 19.4. Suppression du feature flag `ai_catalog_internal_visibility`.

{{< /history >}}

Commencez par créer l'agent externe dans le catalogue d'IA.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour créer un agent externe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **IA** > **Agents**.
1. Sélectionnez **Nouvel agent**.
1. Sous **Informations de base** :
   1. Dans **Nom affiché**, saisissez un nom.
   1. Dans **Description**, saisissez une description.
1. Sous **Visibilité et accès**, pour **Visibilité**, sélectionnez **Privé**, **Restreint** ou **Public**.
1. Sous **Configuration** :
   1. Sélectionnez **Externe**.
   1. Saisissez la configuration de votre agent externe. Vous pouvez écrire votre propre YAML ou modifier un exemple de configuration.
1. Sélectionnez **Créer un agent**.

L'agent externe apparaît dans le catalogue d'IA.

La configuration YAML a une taille maximale. Pour plus d'informations, consultez les [limites de taille de configuration](../ai_catalog.md#configuration-size-limits).

### Créer un agent externe manuellement {#create-an-external-agent-manually}

Si vous préférez ne pas suivre le flux de l'interface utilisateur, vous pouvez créer un agent externe manuellement :

1. Créez un fichier de configuration dans votre projet.
1. Créez un compte de service.
1. Créez un déclencheur qui détermine comment vous appelez l'agent.
1. Utilisez l'agent.

Dans ce cas, vous créez manuellement le compte de service utilisé pour exécuter l'agent.

#### Créer un fichier de configuration {#create-a-configuration-file}

Si vous créez des agents externes en ajoutant manuellement des fichiers de configuration, vous devez créer un fichier de configuration différent pour chaque agent externe.

Prérequis :

- Vous devez disposer du rôle Développeur, Chargé de maintenance ou Propriétaire pour le projet.

Pour créer un fichier de configuration :

1. Dans votre projet, créez un fichier YAML, par exemple : `.gitlab/duo/flows/claude.yaml`
1. Remplissez le fichier en utilisant [l'un des exemples de fichier de configuration](external_examples.md).

#### Créer un compte de service {#create-a-service-account}

Vous devez créer [un compte de service](../../profile/service_accounts.md) ayant accès aux projets dans lesquels vous prévoyez d'utiliser un agent externe.

Lorsque l'agent s'exécute, il utilise une combinaison des appartenances de l'utilisateur et des appartenances du compte de service. Cette combinaison est appelée [identité composite](../composite_identity.md).

Prérequis :

- Sur GitLab Self-Managed, vous devez disposer de l'un des éléments suivants :
  - Accès administrateur à l'instance.
  - Le rôle Propriétaire pour un groupe principal et [la permission de créer des comptes de service](../../../administration/settings/account_and_limit_settings.md#allow-top-level-group-owners-to-create-service-accounts).

Chaque projet qui mentionne un agent externe doit disposer d'un [compte de service de groupe](../../profile/service_accounts.md) unique. Mentionnez le nom d'utilisateur du compte de service lorsque vous assignez des tâches à l'agent externe.

Si vous créez un agent externe depuis le catalogue d'IA et l'activez dans un groupe principal, un compte de service est automatiquement créé avec le nom `ai-<agent>-<group>`. Par exemple, si vous activez un agent nommé `Claude code agent` dans le groupe `GitLab Duo`, le nom du compte de service est `ai-claude-code-agent-gitlab-duo`.

> [!warning]
> Si vous utilisez le même compte de service dans plusieurs projets, cela donne à l'agent externe associé à ce compte de service l'accès à tous ces projets.

Pour configurer le compte de service, effectuez les actions suivantes. Si vous ne disposez pas des permissions suffisantes, demandez l'aide de votre administrateur d'instance ou du propriétaire du groupe principal.

1. Pour le groupe principal, [créez un compte de service](../../profile/service_accounts.md#create-a-service-account). Les comptes de service créés pour l'instance ne sont pas pris en charge.

   > [!note]
   > Lorsque vous configurez un compte de service existant en tant qu'agent externe, aucun jeton d'accès personnel ne peut être associé à ce compte. Ce comportement est conçu pour garantir la sécurité des comptes de service.

1. [Créez un jeton d'accès personnel pour le compte de service](../../profile/service_accounts.md#create-a-personal-access-token-for-a-service-account) avec les [portées](../../../security/tokens/access_token_scopes.md) suivantes :
   - `write_repository`
   - `api`
   - `ai_features`
1. [Ajoutez le compte de service à votre projet](../../project/members/_index.md#add-users-to-a-project) avec le rôle Développeur. Cela garantit que le compte de service dispose des permissions minimales nécessaires.

Lorsque vous ajoutez le compte de service à votre projet, vous devez saisir le nom exact du compte de service. Si vous saisissez le mauvais nom, l'agent externe ne fonctionne pas.

#### Créer un déclencheur {#create-a-trigger}

Vous devez maintenant [créer un déclencheur](../triggers/_index.md), qui détermine quand l'agent externe s'exécute.

Par exemple, vous pouvez spécifier que l'agent doit être déclenché lorsque vous mentionnez un compte de service dans une discussion, ou lorsque vous assignez le compte de service en tant que relecteur.

## Activer ou désactiver les agents externes {#turn-external-agents-on-or-off}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/work_items/594615) dans GitLab 19.0.

{{< /history >}}

Par défaut, les agents externes sont activés. Vous pouvez les activer ou les désactiver pour un groupe principal ou pour une instance.

Lorsque les agents externes sont désactivés :

- Les utilisateurs ne peuvent pas créer, activer, désactiver, modifier ou exécuter des agents externes. Cela inclut les agents externes gérés par GitLab et les agents externes personnalisés.
- Les agents externes existants ne sont plus visibles dans le projet sous **IA** > **Agents** > **Activé**.
- Les agents externes créés dans le projet apparaissent sous **IA** > **Agents** > **Gérés**, mais ne peuvent pas être modifiés ni exécutés.
- Les [agents personnalisés](custom.md) et les [agents par défaut](foundational_agents/_index.md) restent disponibles.

{{< tabs >}}

{{< tab title="GitLab.com" >}}

Prérequis :

- Vous devez avoir le rôle Propriétaire pour le groupe.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Agents et flux personnalisés et externes**, cochez ou décochez la case **Autoriser les agents externes**.
1. Sélectionnez **Enregistrer les modifications**.

Ce paramètre se répercute sur tous les sous-groupes du groupe.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

Prérequis :

- Vous devez être administrateur.

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sélectionnez **Modifier la configuration**.
1. Sous **Agents et flux personnalisés et externes**, cochez ou décochez la case **Autoriser les agents externes**.
1. Sélectionnez **Enregistrer les modifications**.

Lorsque le paramètre défini pour l'instance est désactivé, les paramètres définis pour le groupe ne peuvent pas le remplacer.

{{< /tab >}}

{{< /tabs >}}
