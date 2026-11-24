---
title: Connecter des agents connectés en externe (ECA) à la gouvernance IA
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: software_supply_chain_security
documentation_link: "../../../user/ai-governance/externally-connected-agents"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/633489
categories: [ AI Governance ]
level: primary
weight: 50
---

Auparavant, le [tableau de bord de gouvernance IA](../../../user/ai-governance/governance-dashboard.md) affichait uniquement l'activité des agents de la plateforme GitLab Duo Agent Platform. Cela vous offrait une visibilité totale sur l'ensemble de vos agents de la plateforme Agent Platform, notamment les sessions qu'ils exécutaient, les appels d'outils, les MCP utilisés, ainsi que les entrées et sorties des prompts de l'utilisateur et de l'agent respectivement.

Avec le release GitLab 19.5, après une configuration unique via `glab govern setup`, vous pouvez désormais étendre la visibilité de la gouvernance au-delà des seuls agents de la plateforme GitLab Duo Agent Platform, et connecter des agents connectés en externe (ECA) tels que Claude Code, Cursor et Codex à la gouvernance IA de GitLab en utilisant l'interface de ligne de commande GitLab (`glab`).

Lorsque **Autoriser les agents externes** et **Stocker les événements d'audit IA** sont activés, les équipes chargées de la sécurité et de la conformité obtiennent une visibilité sur les ECA qui s'exécutent en dehors de GitLab, aux côtés de vos agents de la plateforme GitLab Duo Agent Platform. Chaque session d'agent éligible est capturée, notamment qui l'a exécutée, quel agent, quel projet et à quel moment, avec les sessions et les appels d'outils qui apparaissent dans le tableau de bord de gouvernance IA et le rapport d'événements d'audit IA. Les événements d'audit sont également transmis à votre SIEM via le streaming d'événements d'audit.

La sortie des outils n'est pas envoyée, à l'exception des courts messages d'erreur provenant des appels d'outils ayant échoué.

Cette fonctionnalité est en version bêta. Partagez vos commentaires dans le [ticket 633489](https://gitlab.com/gitlab-org/gitlab/-/work_items/633489).
