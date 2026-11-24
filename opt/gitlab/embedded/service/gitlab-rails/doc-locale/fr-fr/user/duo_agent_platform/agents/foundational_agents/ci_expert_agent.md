---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments
title: Agent CI Expert
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/587460) en tant que [version bêta](../../../../policy/development_stages_support.md#beta) dans GitLab 18.10 [avec un feature flag](../../../../administration/feature_flags/_index.md) nommé `foundational_pipeline_authoring_agent`. Fonctionnalité désactivée par défaut.
- Feature flag [supprimé](https://gitlab.com/gitlab-org/gitlab/-/issues/588564) dans GitLab 19.0.
- [Disponibilité générale](https://gitlab.com/groups/gitlab-org/-/work_items/21405) dans GitLab 19.2.

{{< /history >}}

L'agent CI Expert est un agent spécialisé qui vous aide à créer, déboguer et optimiser des pipelines CI/CD GitLab. Il combine :

- Une expertise approfondie de la syntaxe et de la configuration CI/CD de GitLab.
- La connaissance des stratégies d'optimisation des pipelines et des meilleures pratiques.

Utilisez l'agent CI Expert lorsque vous avez besoin d'aide pour :

- Création de pipeline : générer des configurations `.gitlab-ci.yml` de zéro en fonction des exigences de votre projet.
- Explication de la syntaxe : comprendre les mots-clés CI/CD et les options de configuration.
- Débogage : analyser les job logs et résoudre les échecs de pipeline.
- Optimisation : améliorer les performances du pipeline grâce à la mise en cache, la parallélisation et l'utilisation du mot-clé `needs` pour permettre aux jobs de démarrer plus tôt.
- Implémenter une utilisation appropriée des mots-clés CI/CD, notamment `rules`, `artifacts`, `services` et `environments`.

## Accéder à l'agent CI Expert {#access-the-ci-expert-agent}

Prérequis :

- Les agents par défaut doivent être [activés](_index.md#turn-foundational-agents-on-or-off).

Pour accéder à l'agent CI Expert :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à** et trouvez votre projet.
1. Dans la barre latérale GitLab Duo, sélectionnez **Ajouter une discussion** ({{< icon name="pencil-square" >}}).
1. Dans la liste déroulante, sélectionnez **CI Expert**.

   Une conversation Chat s'ouvre dans la barre latérale GitLab Duo située à droite de l'écran.
1. Saisissez votre question ou demande relative à CI/CD. Pour obtenir les meilleurs résultats de votre demande :

   - Décrivez le type de votre projet et la stack technologique utilisée.
   - Partagez votre fichier `.gitlab-ci.yml` existant si vous en avez un.
   - Précisez vos objectifs. Par exemple, des builds plus rapides, un déploiement sur Kubernetes ou l'exécution de tests en parallèle.

### Exemples de prompts {#example-prompts}

- « Créer un pipeline CI/CD pour mon projet Node.js avec des tests et un build Docker. »
- « Comment mettre en cache les dépendances pour accélérer mes builds ? »
- « Ajouter une étape de déploiement à mon pipeline pour Kubernetes. »
- « Quelle est la différence entre `cache` et `artifacts` ? »
- « Aide-moi à configurer des tests parallèles pour ma suite de tests. »
- « Comment utiliser `needs` pour permettre aux jobs de démarrer plus tôt ? »
- « Explique ce que fait cette configuration CI/CD : (coller la configuration) »
- « Comment configurer un pipeline multi-projets ? »
- « Quelle est la meilleure façon de gérer les secrets dans mon pipeline ? »
- « Aide-moi à optimiser mon pipeline pour réduire les temps de build. »
- « Comment exécuter des jobs uniquement sur des merge requests ? »
- « Créer un `.gitlab-ci.yml` pour mon projet Python avec pytest et le linting. »
- « Comment utiliser les artifacts pour transmettre des données entre les jobs ? »
