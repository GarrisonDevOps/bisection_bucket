---
title: Avertissements anticipés pour les plafonds de dépenses GitLab Flex
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_flex_dashboard/#usage-notifications"
work_item: https://gitlab.com/gitlab-org/customers-gitlab-com/-/issues/18962
categories: [ Consumables Cost Management ]
level: secondary
---

GitLab 19.3 a introduit des notifications par e-mail pour les seuils de réservation et pour le moment où une fonctionnalité plafonnée est coupée. Le plafond de dépenses lui-même ne comportait aucun avertissement anticipé, de sorte que le premier e-mail concernant un plafond n'arrivait qu'une fois l'utilisation déjà interrompue.

GitLab envoie désormais un e-mail aux responsables de compte de facturation lorsque l'utilisation à la demande d'une fonctionnalité atteint 50 % ou 80 % de son plafond de dépenses mensuel, en indiquant la fonctionnalité et le plafond en crédits. Seul le seuil le plus élevé franchi est envoyé, au plus une fois par fonctionnalité et par période de facturation. Les plafonds inférieurs à 10 $ sont ignorés, afin qu'un plafond faible ne génère pas de notifications superflues.
