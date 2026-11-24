---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Sécurisez votre dépôt avec la protection des branches, les règles d'approbation et les contrôles d'accès."
title: Protéger votre dépôt
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

La protection du dépôt empêche les modifications non autorisées de votre base de code tout en maintenant les workflows de développement. Ces contrôles vous aident à résoudre les problèmes de développement courants, notamment :

- Les commits accidentels vers les branches de production ou les branches protégées.
- Les données sensibles exposées dans les historiques de commits.
- Les processus de revue de code contournés.
- Les modifications non autorisées de fichiers critiques.
- La paternité des commits non vérifiée.
- Le code non conforme qui entre dans la branche principale.

En combinant différentes méthodes de protection, vous créez des points de validation qui fonctionnent ensemble pour appliquer les normes de votre organisation.

Les éditions GitLab supérieures ont accès à des outils supplémentaires pour appliquer une analyse de sécurité complète, imposer la conformité et gérer les vulnérabilités dans plusieurs projets et groupes. Dans ces environnements, certaines des méthodes de protection peuvent déjà être appliquées par votre organisation. Pour plus de détails sur ces outils de sécurité avancés, voir [sécuriser votre application](../../application_security/secure_your_application.md).

## Méthodes de protection {#protection-methods}

GitLab fournit plusieurs méthodes de protection qui fonctionnent ensemble pour sécuriser votre dépôt. Chaque méthode répond à différents besoins de sécurité et peut être combinée pour une protection complète.

| Méthode de protection | Description | Quand l'utiliser | Instance | Groupes | Projets |
|-------------------|-------------|-------------|----------|--------|----------|
| [Branches protégées](branches/protected.md)                      | Contrôle les permissions sur les branches pour garantir la stabilité et la qualité du code.                         | Contrôlez qui peut pousser et fusionner, empêchez la suppression accidentelle, imposez les revues ou réglez les permissions de force push. | {{< no >}}  | {{< yes >}} | {{< yes >}} |
| [Approbations des merge requests](../merge_requests/approvals/_index.md) | Processus de revue qui exige des approbations avant que les modifications ne soient fusionnées.                                   | Exigez des revues de code, créez des règles d'approbation ou configurez les paramètres d'approbation.                                      | {{< no >}}  | {{< yes >}} | {{< yes >}} |
| [Règles de poussée](push_rules.md)                                      | Hooks Git pre-receive qui valident les commits, les fichiers et les tags avant qu'ils n'entrent dans le dépôt. | Évaluez le contenu des commits, appliquez des règles de nommage des branches, empêchez la suppression des tags ou exigez des commits signés.              | {{< yes >}} | {{< yes >}} | {{< yes >}} |
| [Propriétaires du code](../codeowners/_index.md)                           | Définit qui a l'expertise pour des fichiers et des répertoires spécifiques de votre base de code.                 | Exigez l'approbation d'un expert pour les modifications de fichiers spécifiques ou identifiez les parties responsables de la maintenance du code.       | {{< no >}}  | {{< no >}}  | {{< yes >}} |
| [Vérifications de statut](../merge_requests/status_checks.md)              | Appels API vers des systèmes externes qui valident le statut des merge requests.                              | Intégrez des outils de workflow tiers ou validez par rapport à des exigences de qualité externes.                      | {{< no >}}  | {{< no >}}  | {{< yes >}} |

## Règles des branches {#branch-rules}

Pour vous aider à gérer plusieurs méthodes de protection, GitLab fournit une interface unifiée de [règles des branches](branches/branch_rules.md) pour les branches protégées, les règles d'approbation et les vérifications de statut. Utilisez la page **Règles des branches** dans les paramètres de votre projet pour configurer toutes les protections des branches depuis un seul emplacement, consulter le statut de protection de toutes les branches et gérer des combinaisons de protections complexes.

> [!note]
> Pour la protection au niveau du groupe, configurez les branches protégées et les règles de poussée dans les paramètres de votre groupe. La page **Règles des branches** n'est disponible que dans les projets. Les règles de groupe s'appliquent à tous les projets du groupe et fonctionnent conjointement avec les règles spécifiques aux projets que vous créez.

## Configurer votre stratégie de protection {#configure-your-protection-strategy}

Choisissez des méthodes de protection en fonction de votre workflow et de vos exigences de sécurité. Voici des exemples de stratégies.

### Protection de base {#baseline-protection}

Pour établir des normes de sécurité cohérentes dans tous les dépôts :

- Configurez la protection de la branche par défaut pour le groupe afin de protéger automatiquement les nouveaux projets.
- Configurez des branches protégées pour contrôler qui peut pousser et fusionner.
- Exigez des approbations de merge requests pour imposer la revue par les pairs.

### Protection complète {#comprehensive-protection}

Pour sécuriser les projets critiques avec une protection en couches :

- Configurez des branches protégées et des règles d'approbation pour contrôler qui peut pousser et fusionner.
- Exigez des approbations du propriétaire du code pour les fichiers contenant une logique sensible.
- Imposez des commits signés pour vérifier l'identité de l'auteur.
- Ajoutez des vérifications de statut pour valider par rapport aux tests automatisés.
- Appliquez des règles de poussée à un groupe pour imposer des normes à tous les projets.

### Protection ciblée {#targeted-protection}

Pour répondre à des exigences de sécurité spécifiques :

- Exigez l'approbation du propriétaire du code lorsque les fichiers nécessitent une revue d'expertise dans le domaine.
- Appliquez des règles de poussée pour maintenir les normes de commit et les restrictions de contenu.
- Ajoutez des vérifications de statut lorsqu'une validation externe est requise.
- Configurez des règles d'approbation pour les exigences spécifiques au workflow.

## Démarrer {#get-started}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire pour le projet, ou du rôle Propriétaire pour le groupe.
- Identifiez les branches qui nécessitent une protection.
- Déterminez vos exigences en matière de conformité et de sécurité.

Pour configurer et mettre en œuvre la protection du dépôt :

1. Choisissez votre portée :
   - Pour les règles de groupe, accédez aux **Paramètres** > **Dépôt** de votre groupe.
   - Pour les règles spécifiques au projet, accédez aux **Paramètres** > **Dépôt** > **Règles des branches** de votre projet.

1. Définissez la protection de base :
   - Créez des branches protégées pour votre branche par défaut et les autres branches critiques.
     - Dans les paramètres du groupe : **Paramètres** > **Dépôt** > **Branches protégées**.
     - Dans les paramètres du projet : **Paramètres** > **Dépôt** > **Règles des branches**.
   - Configurez les permissions de fusion et les exigences d'approbation dans **Paramètres** > **Requêtes de fusion** > **Approbations des requêtes de fusion**.

1. Ajoutez des exigences de revue :
   - Définissez les propriétaires du code dans le fichier `CODEOWNERS` pour des fichiers spécifiques.
   - Configurez des règles d'approbation dans **Paramètres** > **Requêtes de fusion**.

1. Activez les contrôles de sécurité :
   - Configurez les règles de poussée :
     - Pour les groupes : **Paramètres** > **Dépôt** > **Règles de poussée**.
     - Pour les projets : **Paramètres** > **Dépôt** > **Règles de poussée**.
   - Activez les commits signés dans **Paramètres** > **Dépôt** > **Règles de poussée** > **Rejeter les validations sans signature**.

1. Testez votre configuration :
   - Créez une merge request de test.
   - Vérifiez que les règles de protection se déclenchent correctement.
   - Ajustez les paramètres en fonction des résultats.

## Sujets connexes {#related-topics}

- [Règles des branches](branches/branch_rules.md)
- [Règles de poussée](push_rules.md)
- [Les merge requests](../merge_requests/_index.md)
- [Propriétaires du code](../codeowners/_index.md)
- [Rôles et autorisations](../../permissions.md)
