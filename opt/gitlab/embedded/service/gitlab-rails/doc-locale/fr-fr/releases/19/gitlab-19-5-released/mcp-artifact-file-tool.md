---
title: "Outil d'artefact CI/CD du serveur MCP"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: agent_foundations
documentation_link: "../../../user/model_context_protocol/mcp_server_tools"
work_item: https://gitlab.com/gitlab-org/gitlab/-/issues/585022
categories: [ Agent Tools ]
level: secondary
weight: 50
---

Auparavant, si vous aviez besoin qu'un agent vérifie quelque chose dans les artefacts de build d'un job CI/CD, il devait télécharger et décompresser l'intégralité de l'archive pour lire un seul fichier. Désormais, l'outil MCP `get_artifact_file` permet à votre agent de lire un seul fichier directement depuis les artefacts d'un job, qu'il s'agisse d'un journal, d'un rapport généré ou d'une fixture de test.
