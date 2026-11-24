---
stage: Software Supply Chain Security
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "API REST pour vérifier et évaluer le pare-feu des dépendances d'un projet."
title: API du pare-feu des dépendances
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated
- Statut : version expérimentale

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/groups/gitlab-org/-/work_items/23242) dans GitLab 19.4 [avec un feature flag](../administration/feature_flags/_index.md) nommé `dependency_firewall_phase1`. Fonctionnalité désactivée par défaut.

{{< /history >}}

> [!flag]
> La disponibilité de cette fonctionnalité est contrôlée par un feature flag. Pour plus d'informations, consultez l'historique. Cette fonctionnalité est disponible à des fins de test, mais n'est pas prête pour une utilisation en production.

Utilisez cette API pour interagir avec le pare-feu des dépendances d'un projet. Le pare-feu des dépendances bloque les paquets qui ne satisfont pas aux politiques de sécurité d'un projet avant qu'ils ne soient récupérés.

## Récupérer le statut du pare-feu des dépendances pour un projet {#retrieve-status-of-dependency-firewall-for-a-project}

Récupère le statut du pare-feu des dépendances pour un projet spécifié. Utilisez ce point de terminaison pour déterminer s'il faut ignorer le pare-feu pour l'intégralité d'une exécution. Les projets dont le pare-feu est désactivé renvoient une réponse de succès plutôt que `404 Not Found`, ce qui permet de les distinguer des projets auxquels vous n'avez pas accès.

Ce point de terminaison accepte un jeton d'accès personnel, un jeton d'accès au projet, un jeton d'accès de groupe, un jeton OAuth ou un [jeton de job CI/CD](../ci/jobs/ci_job_token.md). Les jetons de déploiement ne sont pas pris en charge. Les requêtes non authentifiées sont refusées, y compris pour les projets publics.

Un jeton de job CI/CD ne nécessite aucune autorisation précise particulière. Ce qui le contraint, c'est le projet dans lequel son job s'exécute : un jeton de job ne peut vérifier que ce projet. Toute demande pour un autre projet est refusée avec `403 Forbidden`, même si le projet cible autorise le projet du job dans sa [liste d'autorisation des jetons de job entrants](../ci/jobs/ci_job_token.md), et indépendamment des autorisations précises accordées par cette entrée de liste. Le statut du pare-feu d'un projet n'est pas une information dont le pipeline d'un autre projet a besoin.

Prérequis :

- Vous devez avoir la permission de lire le projet.

```plaintext
GET /projects/:id/dependency_firewall/enablement
```

Attributs pris en charge :

| Attribut | Type              | Obligatoire | Description |
| --------- | ----------------- | -------- | ----------- |
| `id`      | entier ou chaîne | oui      | L'identifiant ou le [chemin encodé en URL du projet](rest/_index.md#namespaced-paths). |

En cas de succès, renvoie [`200 OK`](rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut  | Type    | Description |
| ---------- | ------- | ----------- |
| `enabled`  | Booléen | Indique si le pare-feu des dépendances est activé pour le projet. Une réponse combinée unique : la réponse n'indique pas si c'est la licence ou le paramètre de l'espace de nommage qui l'a produite. |

Codes de réponse possibles :

| Code de statut | Description |
| ----------- | ----------- |
| `401`       | Non autorisé. La requête ne comportait pas d'authentification valide. |
| `403`       | Interdit. Le credential n'est pas autorisé à utiliser ce point de terminaison : un jeton de job CI/CD pour tout projet autre que celui dans lequel son job s'exécute, ou un jeton à portée fine sans permission de lire le projet. Un utilisateur qui ne peut pas lire le projet reçoit `404` à la place. |
| `404`       | Introuvable. La signification dépend de la clé utilisée dans le corps de la réponse : `enabled`, `message` ou `error`. Consultez les indications après ce tableau. |
| `429`       | Trop de requêtes. Vous avez dépassé la limite de débit pour ce point de terminaison, dont la portée est limitée à l'utilisateur appelant. Cette limite est distincte de la limite applicable aux autres points de terminaison du projet. |

Tant que le feature flag est désactivé, le point de terminaison renvoie `404` plutôt que `200`, car le point de terminaison n'est pas encore disponible en général. Une réponse `404` signifie donc l'une de ces trois choses, et un client les distingue selon la clé utilisée dans le corps de la réponse, et non selon la formulation du texte :

- Un corps avec une clé `enabled`, tel que `{"enabled": false}`, signifie que le feature flag est désactivé pour ce projet. Le pare-feu n'est pas actif, donc un client peut l'ignorer pour l'exécution.
- Un corps avec une clé `error`, tel que `{"error":"404 Not Found"}`, signifie que ce point de terminaison n'existe pas sur l'instance. Par exemple, l'instance pourrait exécuter GitLab Community Edition, ou une version publiée avant l'ajout de ce point de terminaison. Un client devrait revenir à son comportement précédent plutôt que de signaler un problème de configuration.
- Un corps avec une clé `message` signifie que le point de terminaison existe et a refusé la requête. Le projet n'existe pas ou vous ne pouvez pas le lire. Un client doit signaler un problème de configuration et ne doit pas traiter le projet comme non protégé.

Ne fondez pas cette décision sur le texte du message. Un appelant dont le projet est illisible obtient `{"message":"404 Project Not Found"}`, mais un jeton à portée fine qui n'a pas accès au projet obtient `{"message":"404 Not Found"}`, ce qui se lit de la même façon que le cas du point de terminaison manquant si vous comparez uniquement la formulation.

Exemple de requête :

```shell
curl --request GET \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --url "https://gitlab.example.com/api/v4/projects/1/dependency_firewall/enablement"
```

Exemple de réponse :

```json
{
  "enabled": true
}
```

Pour vous authentifier depuis un job de pipeline, utilisez un [jeton de job CI/CD](../ci/jobs/ci_job_token.md) avec l'en-tête `JOB-TOKEN` :

```shell
curl --request GET \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
  --url "https://gitlab.example.com/api/v4/projects/1/dependency_firewall/enablement"
```

## Évaluer un paquet par rapport aux politiques du pare-feu des dépendances pour un projet {#evaluate-a-package-against-dependency-firewall-policies-for-a-project}

Évalue un seul paquet par rapport aux politiques du pare-feu des dépendances pour un projet spécifié.

Ce point de terminaison accepte un jeton d'accès personnel, un jeton d'accès au projet, un jeton d'accès de groupe, un jeton OAuth ou un [jeton de job CI/CD](../ci/jobs/ci_job_token.md). Un jeton de job ne peut évaluer des paquets que pour le projet dans lequel son job s'exécute : un jeton de job pour tout autre projet est refusé avec un code de statut `403 Forbidden`, même si le projet cible autorise le projet du job dans sa [liste d'autorisation des jetons de job entrants](../ci/jobs/ci_job_token.md). Les jetons de déploiement ne sont pas pris en charge.

Prérequis :

- Vous devez disposer au minimum du rôle Reporter pour le projet. Le registre de paquets n'a pas besoin d'être activé : le pare-feu des dépendances évalue les dépendances récupérées depuis des registres en amont, de sorte que la permission d'évaluation est indépendante du paramètre de registre de paquets du projet.

```plaintext
POST /projects/:id/dependency_firewall/evaluate
```

Attributs pris en charge :

| Attribut   | Type              | Obligatoire | Description |
|-------------|-------------------|----------|-------------|
| `id`        | entier ou chaîne | oui      | L'identifiant ou le [chemin encodé en URL du projet](rest/_index.md#namespaced-paths). |
| `ecosystem` | Chaîne            | oui      | Écosystème du paquet. L'un des suivants : `cargo`, `composer`, `conan`, `gem`, `golang`, `maven`, `npm`, `nuget`, `pub`, `pypi` ou `swift`. |
| `name`      | Chaîne            | oui      | Nom du paquet, 255 caractères maximum. Pour `maven`, utilisez la forme `groupId:artifactId`, par exemple `com.example:trivial-lib`. Pour `pypi`, les noms sont normalisés selon PEP 503 avant l'évaluation, donc `Flask_Login` et `flask-login` sont équivalents. |
| `version`   | Chaîne            | oui      | Version du paquet, 255 caractères maximum. |
| `operation` | Chaîne            | non       | Opération sur le paquet en cours d'évaluation. L'un des suivants : `download` ou `upload`. Par défaut : `download`. |

En-têtes de requête :

- `X-Gitlab-Dependency-Firewall-Session-Id` : facultatif. Regroupe toutes les évaluations issues d'une seule invocation du gestionnaire de paquets, afin qu'une seule commande d'installation déclenchant une évaluation par paquet puisse être corrélée par cette valeur. GitLab enregistre la valeur dans l'événement d'audit et l'événement d'analyse pour l'évaluation, et la traite comme une valeur opaque sans la vérifier.

La valeur doit comporter entre 1 et 255 caractères, et ne peut contenir que des lettres, des chiffres, des underscores et des tirets. Si la valeur ne satisfait pas à ces contraintes, GitLab l'ignore et l'évaluation se poursuit comme si vous n'aviez pas envoyé l'en-tête. La requête n'échoue pas.

En cas de succès, renvoie [`200 OK`](rest/troubleshooting.md#status-codes) et les attributs de réponse suivants :

| Attribut | Type   | Description |
|-----------|--------|-------------|
| `outcome` | Chaîne | Résultat de l'évaluation. L'une des valeurs `allowed`, `warned` ou `blocked`. |
| `reason`  | Chaîne | Message décrivant pourquoi le paquet a reçu un avertissement ou a été bloqué. Indique la politique correspondante. `null` lorsque `outcome` est `allowed`. |

L'attribut `outcome` a l'une des valeurs suivantes :

- `allowed` : aucune règle de politique ne correspond au paquet. Un projet dont le pare-feu des dépendances est activé mais sans politique associée renvoie toujours `allowed`. Un résultat `allowed` ne constitue pas une affirmation que GitLab détient des données de vulnérabilité ou de licence pour le paquet. Un paquet absent de la base de données de métadonnées de paquets est également autorisé.
- `warned` : une règle de politique correspond au paquet, et la politique correspondante est en mode avertissement.
- `blocked` : une règle de politique correspond au paquet, et la politique correspondante est en mode application.

Ce point de terminaison peut également renvoyer les codes de statut suivants :

| Code de statut | Code | Description |
|-------------|------|-------------|
| `400` | Aucune | `name` ou `version` est vide, ou `ecosystem` ou `operation` n'est pas l'une des valeurs acceptées. |
| `401` | Aucune | La requête n'a pas été authentifiée. |
| `403` | Aucune | L'utilisateur authentifié ne dispose pas au minimum du rôle Reporter pour le projet, ou la requête a utilisé un jeton de job CI/CD pour un projet autre que celui dans lequel son job s'exécute. |
| `404` | Aucune | Le projet n'existe pas, l'utilisateur authentifié n'y a pas accès, ou le feature flag `dependency_firewall_phase1` est désactivé. |
| `422` | `dependency_firewall_not_enforced` | Le pare-feu des dépendances n'est pas activé pour le projet. |
| `429` | Aucune | La limite de débit pour ce point de terminaison a été dépassée. La limite est définie selon la combinaison du projet et de l'utilisateur. |
| `503` | `dependency_firewall_evaluation_failed` | Une recherche de métadonnées de paquet n'a pas abouti. Bloquez la récupération. |

Exemple de requête :

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --header "Content-Type: application/json" \
  --url "https://gitlab.example.com/api/v4/projects/1/dependency_firewall/evaluate" \
  --data '{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}'
```

Exemple de réponse :

```json
{
  "outcome": "blocked",
  "reason": "Package 'lodash' violates 'deny-mit' policy"
}
```

Exemple de réponse pour un projet dont le pare-feu des dépendances est activé mais sans politique associée :

```json
{
  "outcome": "allowed",
  "reason": null
}
```

Depuis un job de pipeline, authentifiez-vous avec un [jeton de job CI/CD](../ci/jobs/ci_job_token.md) :

```shell
curl --request POST \
  --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
  --header "Content-Type: application/json" \
  --url "https://gitlab.example.com/api/v4/projects/1/dependency_firewall/evaluate" \
  --data '{"ecosystem": "npm", "name": "lodash", "version": "4.17.15"}'
```
