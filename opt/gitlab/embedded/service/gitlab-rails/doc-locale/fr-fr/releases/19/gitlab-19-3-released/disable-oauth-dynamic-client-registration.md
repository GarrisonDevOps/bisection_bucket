---
title: "Désactiver l'enregistrement dynamique de clients OAuth pour MCP"
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../administration/settings/account_and_limit_settings/#oauth-dynamic-client-registration"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/601438
categories: [ System Access ]
level: secondary
weight: 50
---

Auparavant, les clients MCP et les outils d'IA pouvaient enregistrer automatiquement des applications OAuth sur votre instance via l'enregistrement dynamique de clients (DCR), sans possibilité de le désactiver. Cela rendait difficile pour les administrateurs des instances GitLab Self-Managed et GitLab Dedicated de contrôler quels clients OAuth pouvaient se connecter.

Vous pouvez désormais désactiver entièrement le DCR à l'aide de l'API des paramètres d'application, ce qui vous donne un contrôle total sur les clients OAuth autorisés à accéder à votre instance. Lorsque le DCR est désactivé, les clients doivent utiliser une application OAuth pré-enregistrée au lieu de s'enregistrer automatiquement.
