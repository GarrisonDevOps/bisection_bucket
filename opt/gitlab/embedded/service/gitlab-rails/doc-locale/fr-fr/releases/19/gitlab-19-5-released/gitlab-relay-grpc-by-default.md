---
title: Les connexions GitLab Relay (KAS) utilisent gRPC par défaut
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: verify
documentation_link: ../../../user/clusters/agent/install/
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/23445
categories: [ GitLab Runner Core, Deployment Management ]
level: secondary
---

GitLab Relay (KAS) utilise désormais gRPC par défaut. GitLab.com a annoncé `grpcs://kas.gitlab.com` dans GitLab 19.4. Dans GitLab 19.5, les nouvelles installations via le package Linux et le chart Helm annoncent également `grpcs://`. Les nouvelles installations d'agents se connectent via `grpcs://` au lieu de gRPC encapsulé dans WebSocket, ce qui signifie un seul protocole à router et à dépanner, et moins de surcharge pour chaque connexion.

Les agents qui se connectent déjà via `wss://` fonctionnent, mais vous devriez les migrer. Sur GitLab.com, définissez l'adresse de l'agent sur `grpcs://kas.gitlab.com`. Par exemple, utilisez `--set config.kasAddress=grpcs://kas.gitlab.com` lorsque vous mettez à niveau le chart Helm `gitlab-agent`. Sur GitLab Self-Managed, utilisez l'adresse indiquée dans la [commande d'installation de l'agent](../../../user/clusters/agent/install/_index.md) après la mise à niveau.
