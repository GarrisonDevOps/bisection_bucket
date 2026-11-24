---
title: GitLab Secrets Manager désormais disponible en version bêta ouverte
stage: software_supply_chain_security
level: primary
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed ]
documentation_link: "../../../ci/secrets/secrets_manager/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/21731"
categories: [ Secrets Management ]
weight: 30
---

Dans les versions précédentes de GitLab, GitLab Secrets Manager n'était disponible que pour un groupe fermé de bêta-testeurs. La plupart des équipes s'appuyaient sur des services externes tels que HashiCorp Vault ou AWS Secrets Manager.

GitLab Secrets Manager est désormais disponible en bêta ouverte pour les clients GitLab Premium et GitLab Ultimate sur GitLab.com et GitLab Self-Managed. Lorsque GitLab Secrets Manager est activé, les Propriétaires de projets et de groupes peuvent stocker, récupérer et référencer des secrets CI/CD dans GitLab. Les secrets sont limités à un projet ou un groupe et ne sont accessibles qu'aux jobs de pipeline qui les demandent explicitement.

Pendant la période de version bêta ouverte, GitLab Secrets Manager suit la [politique de prise en charge bêta](../../../policy/development_stages_support.md#beta) et peut ne pas être prêt pour une utilisation en production.

Pour partager vos commentaires, consultez le [ticket 598100](https://gitlab.com/gitlab-org/gitlab/-/issues/598100).
