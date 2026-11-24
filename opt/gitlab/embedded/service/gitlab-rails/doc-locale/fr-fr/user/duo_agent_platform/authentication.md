---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments
title: "Authentification de la plateforme d'agents GitLab Duo"
---

La plateforme d'agents GitLab Duo utilise une chaîne d'authentification multi-jetons avant que les requêtes n'atteignent un fournisseur de modèle.

Le tableau suivant répertorie les types de jetons et la durée de vie (TTL) de chaque jeton.

| Jeton  | Émetteur | TTL    | Comportement d'actualisation                                        |
|--------|--------|--------|---------------------------------------------------------|
| JWT Cloud Connector (auto-signé) | Instance GitLab Dedicated | Une heure  | À chaque requête. |
| Jeton d'accès au service CustomersDot | `customers.gitlab.com`    | Environ trois jours | Via un cron horaire lorsqu'il reste moins de 2 jours. |
| Jeton d'accès OAuth                | Instance GitLab Dedicated | Deux heures  | À chaque workflow.                                 |
| JWT interne du service GitLab Duo Workflow           | Service GitLab Duo Workflow | 1 heure | À chaque workflow avec le RPC `GenerateToken`. |
| JWT d'échange GLGO                 | Passerelle d'IA                | 1 heure                              |  À chaque requête. |
