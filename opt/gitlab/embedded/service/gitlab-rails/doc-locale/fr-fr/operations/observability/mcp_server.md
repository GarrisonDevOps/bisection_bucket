---
stage: none
group: Embody
info: This page is owned by <https://handbook.gitlab.com/handbook/engineering/embody-team/>
description: "Interrogez les données d'observabilité GitLab depuis des assistants IA avec le serveur Model Context Protocol."
ignore_in_report: true
title: "Serveur MCP d'observabilité"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com
- Statut : version bêta

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248200) dans GitLab 19.3 en tant que [version expérimentale](../../policy/development_stages_support.md#experiment).
- [Passage](https://gitlab.com/gitlab-org/gitlab/-/work_items/632757) de la version expérimentale à la [version bêta](../../policy/development_stages_support.md#beta) dans GitLab 19.5.

{{< /history >}}

GitLab Observability fournit un serveur [Model Context Protocol (MCP)](https://modelcontextprotocol.io) pour vous permettre d'interroger vos données d'observabilité depuis des assistants et agents IA en langage naturel.

Une fois connecté, un client compatible MCP peut poser des questions sur vos données de télémétrie et obtenir des réponses basées sur vos propres données. Les clients pris en charge sont notamment Cursor, Claude (Claude Code et Claude Desktop), VS Code et Codex. Par exemple :

- Quel service présente le taux d'erreur le plus élevé au cours de la dernière heure ?
- Afficher les logs d'erreur pour le service de paiement.
- Quelle est la latence p99 pour le service de paiement aujourd'hui ?
- Lister les services qui transmettent des données.

Le serveur MCP peut interroger les métriques, les traces, les logs, les alertes, les tableaux de bord et les services dans votre instance GitLab Observability.

## Prérequis {#prerequisites}

- L'observabilité doit être activée pour votre groupe ou votre projet personnel. Pour les instructions de configuration, consultez [Configurer l'observabilité sur GitLab.com](setup_gitlab_com.md).
- Pour un groupe, vous devez disposer du rôle Developer, Maintainer ou Owner. Pour un projet personnel, vous devez disposer du rôle Owner.
- Vous devez disposer d'un client MCP qui prend en charge les serveurs HTTP distants.

## Obtenir votre clé API {#get-your-api-key}

Le serveur MCP ne possède pas de credentials propres. Chaque utilisateur s'authentifie avec sa propre clé API GitLab Observability, que son client MCP envoie à chaque requête. L'accès est limité à ce que la clé est autorisée à consulter.

Pour créer une clé API :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre groupe ou projet personnel.
1. Dans la barre latérale gauche, sélectionnez **Observabilité** > **Clés API**.
1. Créez une clé et copiez-la.

> [!warning]
> Conservez votre clé API en lieu sûr. Ne la commitez pas dans le système de contrôle de version. Utilisez la gestion des secrets ou la prise en charge des variables d'environnement de votre client MCP, si disponible.

## Obtenir votre point d'arrivée MCP {#get-your-mcp-endpoint}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre groupe ou projet personnel.
1. Dans la barre latérale gauche, sélectionnez **Observabilité** > **Configuration**.
1. Dans la section **Serveur MCP**, copiez le **Point d'arrivée MCP**.

Votre point d'arrivée MCP suit ce format :

```plaintext
https://<namespace_id>.mcp.gitlab-o11y.com/mcp
```

Remplacez `<namespace_id>` par l'ID de l'espace de nommage pour lequel vous avez activé l'observabilité. L'ID de l'espace de nommage correspond à l'ID de votre groupe ou à l'ID de votre espace de nommage personnel si vous avez activé l'observabilité sur un projet personnel.

## Connecter un client {#connect-a-client}

1. Ajoutez le serveur MCP à votre client en tant que nouveau serveur MCP HTTP distant, en utilisant le point d'arrivée que vous avez copié.
1. Lorsque votre client demande une authentification, fournissez la clé API que vous avez créée. Votre client l'envoie en tant qu'en-tête `SIGNOZ-API-KEY`.
1. Vérifiez la connexion dans votre client. Par exemple, listez les outils MCP disponibles, puis commencez à poser des questions sur vos données d'observabilité.

## Outils disponibles {#available-tools}

Le serveur MCP expose des outils pour lire et explorer vos données d'observabilité, notamment :

- Métriques : liste et requête
- Logs : recherche et agrégation
- Traces : recherche et inspection des traces et spans individuelles
- Services : liste et affichage des principales opérations
- Alertes : liste et inspection des règles d'alerte
- Tableaux de bord : liste et inspection des tableaux de bord et vues enregistrées

Votre assistant IA choisit les outils appropriés pour répondre à votre question et retourne des résultats tirés des données de votre instance.

## Sujets connexes {#related-topics}

- [Accéder à l'API Observability](api_access.md)
- [Envoyer des données de télémétrie à GitLab Observability](send.md)
- [Résolution des problèmes d'observabilité](troubleshooting.md)
