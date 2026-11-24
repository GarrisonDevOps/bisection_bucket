---
stage: GitLab Dedicated
group: Switchboard
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "API REST permettant de récupérer le statut et les fenêtres de maintenance d'une instance GitLab Dedicated et de mettre à jour sa configuration."
title: API client Switchboard
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab Dedicated

{{< /details >}}

Utilisez cette API pour récupérer le statut et les fenêtres de maintenance de votre instance [GitLab Dedicated](_index.md), et pour mettre à jour la configuration que vous pouvez modifier dans la console Switchboard.

L'API ne renvoie des données que pour l'instance à laquelle vous disposez d'un accès administrateur de tenant. Vous n'indiquez pas l'instance dans le chemin. L'API la récupère depuis votre accès.

Tous les endpoints utilisent cette URL de base :

```plaintext
https://console.gitlab-dedicated.com/api/customer/v1
```

Si votre console Switchboard possède une URL différente, utilisez l'URL de la console à laquelle vous vous connectez. L'identifiant client et les chemins des endpoints sont identiques pour toutes les consoles.

Prérequis :

- Vous devez disposer d'un accès administrateur de tenant à votre instance dans Switchboard.

## Authentification {#authentication}

Chaque requête doit contenir un jeton d'accès Switchboard OAuth 2.0 dans l'en-tête `Authorization`.

Switchboard fournit des jetons via le flux de code d'autorisation OAuth 2.0 avec Proof Key for Code Exchange (PKCE). Utilisez le client public `switchboard_customer_api_auth`. Ce client n'a pas de secret client. Demandez la portée `read_write`.

Un jeton d'accès expire après 24 heures. La réponse du jeton contient également un jeton d'actualisation. Utilisez le jeton d'actualisation pour obtenir un nouveau jeton d'accès sans connexion dans le navigateur.

### Obtenir un jeton d'accès {#get-an-access-token}

Vous pouvez utiliser n'importe quel client OAuth 2.0 conforme à la norme. Cet exemple utilise [oauth2c](https://github.com/cloudentity/oauth2c).

Pour obtenir un jeton d'accès :

1. Exécutez cette commande :

   ```shell
   oauth2c https://console.gitlab-dedicated.com \
     --client-id switchboard_customer_api_auth \
     --grant-type authorization_code \
     --response-types code \
     --response-mode query \
     --auth-method none \
     --scopes read_write \
     --pkce \
     --redirect-url http://localhost:3290/callback \
     --authorization-endpoint https://console.gitlab-dedicated.com/oauth/authorize \
     --token-endpoint https://console.gitlab-dedicated.com/oauth/token
   ```

   La commande ouvre un navigateur.
1. Connectez-vous à Switchboard.
1. Approuvez la requête.

La commande récupère le callback sur `http://localhost:3290/callback` et affiche le jeton d'accès. Envoyez le jeton avec chaque requête :

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/sla_status"
```

### Actualiser un jeton d'accès {#refresh-an-access-token}

Pour obtenir une nouvelle paire de jetons sans connexion dans le navigateur, envoyez le jeton d'actualisation à l'endpoint de jeton :

```shell
curl --request POST \
  --url "https://console.gitlab-dedicated.com/oauth/token" \
  --data "grant_type=refresh_token" \
  --data "client_id=switchboard_customer_api_auth" \
  --data "refresh_token=<your_refresh_token>"
```

Chaque actualisation retourne un nouveau jeton d'actualisation. Conservez le jeton d'actualisation le plus récent.

Vous pouvez actualiser les jetons pendant 30 jours maximum après la première connexion dans le navigateur. Après 30 jours, ou si Switchboard révoque le jeton, l'endpoint de jeton retourne `invalid_grant`. Pour continuer, obtenez un nouveau jeton d'accès en vous connectant dans le navigateur.

## Limites de débit {#rate-limits}

Switchboard comptabilise les requêtes pour chaque jeton d'accès et pour chaque adresse IP source, par fenêtres d'une minute.

| Limite | Requêtes par minute |
|-------|--------------------------|
| Chaque jeton d'accès | 60 |
| Chaque adresse IP source | 120 |
| Endpoint de jeton (`/oauth/token`), chaque adresse IP source | 20 |

Lorsqu'une limite s'applique, la réponse contient ces en-têtes pour la limite la plus proche de son maximum :

| En-tête | Description |
|--------|-------------|
| `RateLimit-Limit` | Le nombre de requêtes que la limite autorise dans la fenêtre en cours. |
| `RateLimit-Remaining` | Le nombre de requêtes que la limite autorise encore dans la fenêtre en cours. |
| `RateLimit-Reset` | L'heure Unix, en secondes, à laquelle la fenêtre en cours se réinitialise. Cette valeur est une heure, pas un compte à rebours. |

Si une réponse ne contient pas ces en-têtes, aucune limite ne s'est appliquée à la requête. Utilisez les valeurs dans les en-têtes. N'utilisez pas les chiffres du tableau comme valeurs fixes.

Lorsqu'une requête dépasse une limite, l'API retourne `429 Too Many Requests`. L'en-tête `Retry-After` indique le nombre de secondes à attendre. Une requête effectuée alors que vous dépassez une limite compte également contre la limite. Si votre client continue d'envoyer des requêtes, il reste bloqué jusqu'à la réinitialisation de la fenêtre.

## Erreurs {#errors}

Tous les endpoints peuvent retourner ces codes de statut :

| Code de statut | Description |
|-------------|-------------|
| `401 Unauthorized` | Le jeton d'accès n'est pas valide, ou la requête ne contient pas de jeton d'accès. |
| `403 Forbidden` | Vous ne disposez pas de l'accès nécessaire. |
| `404 Not Found` | L'API client n'est pas disponible pour votre instance, ou l'élément n'existe pas. |
| `422 Unprocessable Entity` | Switchboard n'a pas accepté la modification. Le corps de la réponse indique le problème. |
| `429 Too Many Requests` | La requête dépasse une limite de débit. |

Une réponse d'erreur a un attribut `message`. Certaines erreurs ont également un attribut `errors` avec plus de détails.

## Pagination {#pagination}

Les endpoints de liste retournent une page d'éléments. Utilisez ces attributs pour sélectionner une page :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `page` | Entier | Non | Le numéro de page. La première page est `1`. |
| `per_page` | Entier | Non | Le nombre d'éléments par page. Le maximum est `100`. |

La réponse contient un tableau `items` et un objet `meta` :

| Attribut | Type | Description |
|-----------|------|-------------|
| `meta.current_page` | Entier | Le numéro de page de cette réponse. |
| `meta.total` | Entier | Le nombre d'éléments sur toutes les pages. |
| `meta.total_pages` | Entier | Le nombre de pages. |

## Récupérer les détails de l'instance {#retrieve-instance-details}

Récupère les détails de votre instance.

```plaintext
GET /tenant
```

En cas de succès, renvoie [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut | Type | Description |
|-----------|------|-------------|
| `ever_deployed` | Booléen | `true` après le premier déploiement de votre instance. La valeur reste `true` après le déprovisionnement. |
| `external_url` | Chaîne | L'URL de votre instance GitLab. |
| `gitlab_version` | Chaîne | La version GitLab actuellement sur votre instance. |
| `identifier` | Chaîne | L'identifiant stable de votre instance. Utilisez cette valeur lorsque vous contactez le Support à propos de l'instance. |
| `name` | Chaîne | Le nom d'affichage de votre instance. |
| `prerelease_version` | Chaîne | La version préliminaire sur votre instance, si votre instance exécute une version préliminaire. Sinon, `null`. |
| `reference_architecture_label` | Chaîne | La taille de votre instance, par exemple `Up to 10,000 users (XL)`. |
| `regions` | objet | Les régions cloud de votre instance : `primary`, `backup` et `sites`. `null` tant que le compte cloud de votre instance n'est pas configuré. |

Exemple de requête :

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant"
```

Exemple de réponse :

```json
{
  "identifier": "example1a2b3c",
  "name": "Example Corp",
  "external_url": "https://example.gitlab-dedicated.com",
  "gitlab_version": "19.3.3",
  "prerelease_version": null,
  "reference_architecture_label": "Up to 10,000 users (XL)",
  "ever_deployed": true,
  "regions": {
    "primary": "eu-west-1",
    "backup": "eu-central-1",
    "sites": ["eu-west-1"]
  }
}
```

## Récupérer le statut SLA {#retrieve-sla-status}

Récupère le statut de disponibilité le plus récent de votre instance. Le statut affiche les mêmes données que la page **Santé** dans Switchboard.

> [!note]
> Le statut ne correspond pas à votre accord de niveau de service (SLA) contractuel. GitLab calcule le SLA mensuel séparément, avec sa propre agrégation et ses propres exclusions. Un statut `down` ne signifie pas une violation du SLA. L'API ne retourne pas de données historiques. Ne l'utilisez pas comme flux de surveillance ou d'alerte.

```plaintext
GET /tenant/sla_status
```

En cas de succès, renvoie [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut | Type | Description |
|-----------|------|-------------|
| `covered_experiences` | Tableau | Le statut de chaque expérience couverte, par exemple `web`, `git_operations`, `api` et `package_registry`. Chaque élément a `covered_experience`, `status` et `data_as_of`. Vide si `data_available` est `false`. |
| `data_as_of` | Chaîne | L'heure UTC de la minute la plus récente observée par Switchboard. `null` si `data_available` est `false`. |
| `data_available` | Booléen | `true` si la réponse a un statut. `false` si la réponse a un `reason`. |
| `reason` | Chaîne | La raison pour laquelle aucun statut n'est disponible. Défini uniquement si `data_available` est `false`. |
| `status` | Chaîne | Le statut de votre instance au cours de la minute la plus récente observée par Switchboard. `null` si `data_available` est `false`. |

L'attribut `status` a l'une de ces valeurs :

| Valeur | Description |
|-------|-------------|
| `up` | Votre instance ne présente aucun problème connu. |
| `down` | Votre instance connaît une interruption de service. |
| `maintenance_window` | Votre instance est en maintenance planifiée. |
| `insufficient_traffic` | Votre instance a un trafic trop faible pour calculer la disponibilité. Ce statut est habituel lorsque l'instance est peu sollicitée. Il n'indique pas une panne. |

L'attribut `reason` a l'une de ces valeurs :

| Valeur | Description |
|-------|-------------|
| `not_configured` | La génération de rapports SLA n'est pas activée pour votre instance. Si vous attendez des rapports SLA, contactez le Support. |
| `no_data` | La génération de rapports SLA est activée, mais Switchboard ne dispose d'aucune donnée des 6 dernières heures. Cette valeur est habituelle pour une nouvelle instance ou lorsque la génération de rapports s'interrompt brièvement. |
| `upstream_error` | Switchboard a rencontré une erreur temporaire lors de la récupération des données. Réessayez après un court instant. |

Exemple de requête :

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/sla_status"
```

Exemple de réponse :

```json
{
  "data_available": true,
  "status": "up",
  "data_as_of": "2026-10-08T09:41:00.000Z",
  "reason": null,
  "covered_experiences": [
    { "covered_experience": "web", "status": "up", "data_as_of": "2026-10-08T09:41:00.000Z" },
    { "covered_experience": "git_operations", "status": "up", "data_as_of": "2026-10-08T09:41:00.000Z" }
  ]
}
```

## Lister toutes les fenêtres de maintenance {#list-all-maintenance-windows}

Liste toutes les fenêtres de maintenance planifiées de votre instance. La liste contient les fenêtres à venir et les fenêtres terminées.

```plaintext
GET /tenant/maintenances
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `page` | Entier | Non | Le numéro de page. |
| `per_page` | Entier | Non | Le nombre d'éléments par page. Le maximum est `100`. |
| `scope` | Chaîne | Non | Les fenêtres à retourner : `all` (par défaut), `upcoming` ou `past`. `upcoming` affiche d'abord la fenêtre la plus proche. `all` et `past` affichent d'abord la fenêtre la plus récente. |

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et un tableau `items`. Chaque élément a ces attributs :

| Attribut | Type | Description |
|-----------|------|-------------|
| `approval_status` | Chaîne | L'une des valeurs `pending`, `approved` ou `rejected`. |
| `completed_at` | Chaîne | L'heure à laquelle la maintenance s'est terminée. `null` jusqu'à la fin de la maintenance. |
| `emergency` | Booléen | `true` pour une maintenance d'urgence en dehors de la fenêtre habituelle. |
| `end_at` | Chaîne | L'heure de fin planifiée de la fenêtre. |
| `gitlab_version` | Chaîne | La version GitLab déployée par la maintenance. |
| `gitlab_version_pinned` | Booléen | `true` si les mises à niveau de la version GitLab sont suspendues pour votre instance. |
| `id` | Entier | L'identifiant de la fenêtre de maintenance. |
| `previous_gitlab_version` | Chaîne | La version GitLab avant la maintenance. Pour une fenêtre à venir, la version actuellement sur votre instance. |
| `start_at` | Chaîne | L'heure de début planifiée de la fenêtre. |
| `started_at` | Chaîne | L'heure à laquelle la maintenance a démarré. `null` jusqu'au démarrage de la maintenance. |
| `status` | Chaîne | L'un des statuts `planned`, `running`, `completed`, `failed`, `interrupted` ou `not_run`. |

Si la valeur de `scope` n'est pas reconnue, l'API retourne `422 Unprocessable Entity`.

Exemple de requête :

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/maintenances?scope=upcoming"
```

Exemple de réponse :

```json
{
  "items": [
    {
      "id": 4821,
      "start_at": "2026-10-11T21:00:00.000Z",
      "end_at": "2026-10-12T01:00:00.000Z",
      "started_at": null,
      "completed_at": null,
      "status": "planned",
      "approval_status": "approved",
      "emergency": false,
      "gitlab_version": "19.3.4",
      "previous_gitlab_version": "19.3.3",
      "gitlab_version_pinned": false
    }
  ],
  "meta": { "current_page": 1, "total": 1, "total_pages": 1 }
}
```

## Lister tous les changements de configuration {#list-all-configuration-changes}

Liste tous les changements de configuration de votre instance, le plus récent en premier. Chaque changement indique ce qui a changé, quand, et si le changement est appliqué à votre instance.

```plaintext
GET /tenant/config_changes
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `page` | Entier | Non | Le numéro de page. |
| `per_page` | Entier | Non | Le nombre d'éléments par page. Le maximum est `100`. |

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et un tableau `items`. Chaque élément a ces attributs :

| Attribut | Type | Description |
|-----------|------|-------------|
| `completed_at` | Chaîne | L'heure à laquelle le changement a été appliqué à votre instance. `null` jusque-là. |
| `config_type` | Chaîne | Le nom de la configuration qui a changé. |
| `id` | Entier | L'identifiant du changement. |
| `requested_at` | Chaîne | L'heure de la demande de changement. |
| `status` | Chaîne | L'une des valeurs suivantes : `pending`, `queued`, `deployed` ou `failed`. |

Exemple de requête :

```shell
curl --request GET \
  --header "Authorization: Bearer <your_access_token>" \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/config_changes?per_page=20"
```

Exemple de réponse :

```json
{
  "items": [
    {
      "id": 912,
      "config_type": "IP allowlist",
      "status": "deployed",
      "requested_at": "2026-10-06T14:02:11.000Z",
      "completed_at": "2026-10-06T14:20:47.000Z"
    }
  ],
  "meta": { "current_page": 1, "total": 1, "total_pages": 1 }
}
```

## Configuration {#configuration}

Ces endpoints récupèrent et mettent à jour les paramètres que vous pouvez modifier dans la console Switchboard. Chaque endpoint correspond à une section de la console.

Les endpoints `PUT` remplacent la section complète. Envoyez la configuration complète souhaitée. Switchboard supprime les éléments que vous n'envoyez pas. Pour modifier un élément, récupérez la section, modifiez l'élément, puis renvoyez la section complète. Les endpoints `PUT` acceptent la réponse de l'endpoint `GET` correspondant sans modification. Ils ignorent les attributs définis par Switchboard.

Switchboard enregistre chaque modification dans les changements de configuration de votre instance. Les modifications des coordonnées ne sont pas incluses dans cet enregistrement.

### Récupérer la liste d'autorisation IP {#retrieve-ip-allowlist}

Récupère la liste d'autorisation IP de votre instance.

```plaintext
GET /tenant/ip_allowlist
```

En cas de succès, renvoie [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut | Type | Description |
|-----------|------|-------------|
| `addresses` | Tableau | Les adresses autorisées. Chaque élément a `address`, `description`, `status` et `created_at`. |
| `addresses[].address` | Chaîne | Un bloc CIDR IPv4 ou IPv6. |
| `addresses[].created_at` | Chaîne | L'heure à laquelle vous avez ajouté l'adresse. Switchboard définit cette valeur. |
| `addresses[].description` | Chaîne | Une description de l'adresse. |
| `addresses[].status` | Chaîne | Indique si l'adresse est appliquée à votre instance. Switchboard définit cette valeur. |
| `enabled` | Booléen | `true` si l'instance utilise la liste d'autorisation. `false` si l'instance accepte toutes les adresses source. |

### Remplacer la liste d'autorisation IP {#replace-ip-allowlist}

Remplace la liste d'autorisation IP de votre instance.

```plaintext
PUT /tenant/ip_allowlist
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `addresses` | Tableau | Oui | La liste complète des adresses autorisées. Chaque élément a `address` (obligatoire) et `description`. |
| `enabled` | Booléen | Oui | `true` pour utiliser la liste d'autorisation. |

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et la liste d'autorisation mise à jour.

Exemple de requête :

```shell
curl --request PUT \
  --header "Authorization: Bearer <your_access_token>" \
  --header "Content-Type: application/json" \
  --data '{"enabled": true, "addresses": [{"address": "203.0.113.0/24", "description": "Office"}]}' \
  --url "https://console.gitlab-dedicated.com/api/customer/v1/tenant/ip_allowlist"
```

### Récupérer les coordonnées {#retrieve-contact-information}

Récupère les adresses e-mail opérationnelles que GitLab utilise pour vous contacter à propos de votre instance.

```plaintext
GET /tenant/contact_information
```

En cas de succès, renvoie [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut | Type | Description |
|-----------|------|-------------|
| `operational_email_addresses` | Tableau de chaînes de caractères | Les adresses e-mail pour les notifications opérationnelles concernant votre instance. |

### Remplacer les coordonnées {#replace-contact-information}

Remplace les adresses e-mail opérationnelles de votre instance.

```plaintext
PUT /tenant/contact_information
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `operational_email_addresses` | Tableau de chaînes de caractères | Oui | La liste complète des adresses e-mail. |

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et les coordonnées mises à jour.

GitLab définit les contacts internes et les ingénieurs de support assignés. Vous ne pouvez pas les lire ni les modifier avec cette API.

### Récupérer les paramètres d'accès aux ressources {#retrieve-resource-access-settings}

Récupère les principaux AWS pouvant lire le bucket de journaux d'application de votre instance.

```plaintext
GET /tenant/resource_access
```

En cas de succès, renvoie [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut | Type | Description |
|-----------|------|-------------|
| `bucket_read_arns` | Tableau de chaînes de caractères | Les ARN de principaux AWS pouvant lire votre bucket de journaux d'application. |

### Remplacer les paramètres d'accès aux ressources {#replace-resource-access-settings}

Remplace les principaux AWS pouvant lire le bucket de journaux d'application de votre instance.

```plaintext
PUT /tenant/resource_access
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `bucket_read_arns` | Tableau de chaînes de caractères | Oui | La liste complète des ARN de principaux AWS. |

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et les paramètres mis à jour.

### Lister toutes les autorités de certification personnalisées {#list-all-custom-certificate-authorities}

Liste toutes les autorités de certification personnalisées auxquelles votre instance fait confiance.

```plaintext
GET /tenant/custom_certificate_authorities
```

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et un tableau. Chaque élément a ces attributs :

| Attribut | Type | Description |
|-----------|------|-------------|
| `authority` | Chaîne | L'émetteur. Switchboard obtient cette valeur à partir du certificat. |
| `certificate` | Chaîne | Le certificat encodé en PEM. |
| `id` | Entier | L'identifiant de l'autorité de certification. |
| `not_after` | Chaîne | La fin de la période de validité du certificat. |
| `not_before` | Chaîne | Le début de la période de validité du certificat. |

### Remplacer les autorités de certification personnalisées {#replace-custom-certificate-authorities}

Remplace les autorités de certification personnalisées auxquelles votre instance fait confiance.

```plaintext
PUT /tenant/custom_certificate_authorities
```

Attributs pris en charge :

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `certificates` | Tableau de chaînes de caractères | Oui | L'ensemble complet des certificats encodés en PEM à approuver. |

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et la liste mise à jour.

Si un certificat n'est pas valide ou est expiré, Switchboard n'accepte pas la requête. L'erreur indique l'index du certificat.

### Lister tous les fournisseurs SAML SSO {#list-all-saml-sso-providers}

Liste tous les fournisseurs d'authentification unique (SSO) SAML de votre instance, le plus ancien en premier.

```plaintext
GET /tenant/saml_providers
```

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et un tableau de fournisseurs. Chaque fournisseur a les [attributs du fournisseur](#saml-sso-provider-attributes) et un `id`.

### Récupérer un fournisseur SAML SSO {#retrieve-a-saml-sso-provider}

Récupère un fournisseur SAML SSO de votre instance.

```plaintext
GET /tenant/saml_providers/:id
```

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `id` | Entier | Oui | L'identifiant du fournisseur. |

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et le fournisseur. Si le fournisseur n'existe pas, retourne `404 Not Found`.

### Créer un fournisseur SAML SSO {#create-a-saml-sso-provider}

Crée un fournisseur SAML SSO sur votre instance.

```plaintext
POST /tenant/saml_providers
```

Envoyez les [attributs du fournisseur](#saml-sso-provider-attributes).

En cas de succès, retourne [`201 Created`](../../api/rest/troubleshooting.md#status-codes) et le nouveau fournisseur.

### Remplacer un fournisseur SAML SSO {#replace-a-saml-sso-provider}

Remplace un fournisseur SAML SSO de votre instance.

```plaintext
PUT /tenant/saml_providers/:id
```

Envoyez le fournisseur complet. Si vous n'envoyez pas un attribut facultatif, Switchboard l'efface. Par exemple, si vous n'envoyez pas `admin_groups`, Switchboard supprime le mappage des groupes aux administrateurs.

En cas de succès, retourne [`200 OK`](../../api/rest/troubleshooting.md#status-codes) et le fournisseur mis à jour.

### Supprimer un fournisseur SAML SSO {#delete-a-saml-sso-provider}

Supprime un fournisseur SAML SSO de votre instance.

```plaintext
DELETE /tenant/saml_providers/:id
```

En cas de succès, retourne [`204 No Content`](../../api/rest/troubleshooting.md#status-codes).

### Attributs du fournisseur SAML SSO {#saml-sso-provider-attributes}

| Attribut | Type | Obligatoire | Description |
|-----------|------|----------|-------------|
| `enabled` | Booléen | Oui | `true` pour activer le fournisseur. |
| `idp_cert_fingerprint` | Chaîne | Oui | L'empreinte du certificat du fournisseur d'identité. |
| `idp_sso_target_url` | Chaîne | Oui | L'URL SSO du fournisseur d'identité. |
| `label` | Chaîne | Oui | Le nom sur le bouton de connexion. |
| `name_identifier_format` | Chaîne | Oui | Le format de l'identifiant de nom. |
| `admin_groups` | Tableau de chaînes de caractères | Non | Les groupes dont les membres sont administrateurs. |
| `attribute_statements` | objet | Non | Mappages des attributs SAML aux attributs utilisateur. |
| `auditor_groups` | Tableau de chaînes de caractères | Non | Les groupes dont les membres sont auditeurs. |
| `external_groups` | Tableau de chaînes de caractères | Non | Les groupes dont les membres sont des utilisateurs externes. |
| `force_authn` | Booléen | Non | `true` pour que le fournisseur d'identité demande à nouveau une authentification. |
| `groups_attribute` | Chaîne | Non | L'attribut SAML contenant les groupes de l'utilisateur. |
| `issuer` | Chaîne | Non | L'émetteur. |
| `required_groups` | Tableau de chaînes de caractères | Non | Les groupes auxquels un utilisateur doit appartenir pour se connecter. |
| `security` | objet | Non | Paramètres de sécurité SAML. |
| `upstream_two_factor_authn_contexts` | Tableau de chaînes de caractères | Non | Les contextes d'authentification comptant comme authentification à deux facteurs. |

Pour plus d'informations sur ces paramètres, consultez [SAML SSO pour GitLab Dedicated](configure_instance/authentication/saml.md).

## Sujets connexes {#related-topics}

- [Détails de l'instance GitLab Dedicated](tenant_overview.md)
- [Opérations de maintenance GitLab Dedicated](maintenance.md)
