---
title: "Les crédits inclus sont utilisés avant les crédits d'évaluation"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_credits/#usage-order"
work_item: https://gitlab.com/gitlab-org/customers-gitlab-com/-/issues/18961
categories: [ Consumables Cost Management ]
level: secondary
---

Lorsqu'un abonnement disposait de crédits d'évaluation temporaires, toute utilisation puisait d'abord dans ce pool partagé. Les crédits mensuels inclus de chaque utilisateur restaient inactifs jusqu'à l'épuisement du pool d'évaluation, puis étaient réinitialisés en fin de mois.

GitLab consomme désormais en priorité les crédits inclus de chaque utilisateur, et ne puise dans le pool partagé de crédits d'évaluation temporaires qu'une fois que l'utilisateur a épuisé son quota inclus. Le pool d'engagement mensuel, les crédits à facturation unique et les crédits à la demande sont consommés dans le même ordre qu'auparavant, de sorte que votre facture n'est pas affectée.
