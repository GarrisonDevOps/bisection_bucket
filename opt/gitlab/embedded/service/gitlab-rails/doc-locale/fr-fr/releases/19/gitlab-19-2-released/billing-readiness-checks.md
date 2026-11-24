---
title: "Vérifications de la facturation d'utilisation pour GitLab Duo Agent Platform Self-Hosted"
offering: [ self_managed, gitlab_dedicated_for_government ]
tier: [ Premium, Ultimate ]
stage: ai-powered
documentation_link: "../../../administration/gitlab_duo/configure/#run-a-health-check-for-gitlab-duo"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/603196
categories: [ Health & Connectivity ]
level: secondary
---

<!-- categories: Health & Connectivity  -->

Pour les clients GitLab Self-Managed utilisant des modèles auto-hébergés avec une licence en ligne, GitLab Duo Health vérifie désormais que l'instance GitLab peut atteindre les points de terminaison suivants :

- Portail clients
- La passerelle d'IA
- Duo Workflow Service

La connexion à ces points de terminaison est nécessaire pour la facturation d'utilisation.

Auparavant, si un pare-feu bloquait l'un de ces composants, les administrateurs n'avaient aucune indication de problèmes de connectivité jusqu'à ce que les utilisateurs ne puissent plus utiliser une fonctionnalité. Les administrateurs peuvent désormais utiliser cette nouvelle vérification de validation pour diagnostiquer les problèmes et examiner leur liste d'autorisation du pare-feu avant toute interruption pour les utilisateurs.
