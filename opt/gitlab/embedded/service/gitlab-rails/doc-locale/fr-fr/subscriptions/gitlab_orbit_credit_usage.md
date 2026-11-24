---
stage: Orbit
group: Context Systems
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Comprenez comment GitLab Orbit consomme des GitLab Credits, quelles requêtes sont gratuites et quel groupe est facturé."
title: Utilisation des GitLab Credits par GitLab Orbit
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259054) de l'utilisation des GitLab Credits par GitLab Orbit dans GitLab 19.5.

{{< /history >}}

Chaque requête envoyée via l'API REST, le serveur MCP GitLab ou l'endpoint MCP de GitLab Orbit consomme des [GitLab Credits](gitlab_credits.md).

Le client n'a pas d'importance. Les requêtes provenant de GitLab Duo, de vos propres agents, de la CLI GitLab Orbit, du tableau de bord GitLab Orbit et de la navigation dans le code de GitLab consomment toutes des credits.

Les requêtes sur le graphe local, que la CLI GitLab Orbit construit sur votre ordinateur, ne consomment pas de credits. Les requêtes qui n'exécutent pas de recherche, comme les requêtes de schéma et de statut, ne consomment pas de credits.

## Taux de credits {#credit-rate}

Les requêtes consomment des credits selon ce taux :

| Utilisation                           | Taux        | Crédits |
|---------------------------------|-------------|---------|
| Requêtes vers l'API GitLab Orbit | 100 requêtes | 3       |

### Exemples d'estimation de la consommation mensuelle {#monthly-consumption-estimate-examples}

Utilisez ces exemples pour estimer la consommation mensuelle :

- Une équipe de 10 développeurs exécutant chacun 500 requêtes par mois via GitLab Duo ou la CLI GitLab Orbit.
  - Requêtes : 5 000
  - Total mensuel : 150 crédits
- Un groupe de 100 développeurs exécutant chacun 500 requêtes par mois.
  - Requêtes : 50 000
  - Total mensuel : 1 500 crédits
- Un agent qui examine 5 000 merge requests par mois et exécute 30 requêtes pour chaque révision.
  - Requêtes : 150 000
  - Total mensuel : 4 500 crédits

## Capacité du graphe {#graph-capacity}

La capacité du graphe correspond à la taille du graphe GitLab Orbit pour un groupe principal, mesurée en Gio. La limite de capacité du graphe incluse sur GitLab.com et GitLab Dedicated est :

- GitLab Premium : 2 Gio.
- GitLab Ultimate : 5 Gio.

## Groupe facturé {#billed-group}

L'utilisation est facturée au groupe GitLab Orbit par défaut de l'utilisateur. Si l'utilisateur n'appartient qu'à un seul groupe principal avec GitLab Orbit, ce groupe est le groupe par défaut. Si l'utilisateur appartient à plusieurs groupes, il doit sélectionner un [groupe par défaut](../user/profile/preferences.md#choose-which-gitlab-duo-features-use-orbit). Sur GitLab.com, leurs requêtes échouent tant qu'ils ne l'ont pas fait.

## Essais et achats {#trials-and-purchases}

Sur GitLab.com, un utilisateur disposant du rôle Propriétaire pour un groupe principal peut démarrer un essai gratuit de GitLab Orbit. Pour acheter GitLab Orbit, ou pour l'utiliser sur GitLab Self-Managed ou GitLab Dedicated, [contactez l'équipe commerciale](https://about.gitlab.com/sales/).

## Suivre l'utilisation {#track-usage}

Pour suivre l'utilisation de GitLab Orbit, consultez [Utilisation de GitLab Orbit](gitlab_credits_dashboard.md#gitlab-orbit-usage).
