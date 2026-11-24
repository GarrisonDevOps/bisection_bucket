---
title: Révisions de suivi dans le flow Code Review
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
documentation_link: "../../../user/duo_agent_platform/flows/foundational_flows/code_review/#follow-up-reviews"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/21620
categories: [ DAP Code Review ]
level: secondary
weight: 50
---

Dans les versions précédentes de GitLab, lorsque vous demandiez à GitLab Duo de revoir une merge request, il traitait la révision comme une première passe. Il pouvait répéter des conclusions issues de ses fils de discussion précédents, même ceux que vous aviez déjà traités.

Désormais, le flow Code Review utilise les fils de discussion des révisions précédentes de GitLab Duo, y compris vos réponses, pour évaluer les nouveaux changements. GitLab Duo se concentre sur les lignes ajoutées depuis sa dernière révision, ne répète pas les points qu'il a déjà soulevés et répertorie les conclusions en suspens dans son résumé. Si vous répondez sur un fil de discussion pour expliquer pourquoi le code est correct, GitLab Duo ne soulève pas à nouveau ce point.

Pour démarrer une révision de suivi, demandez à GitLab Duo de revoir la merge request. Lorsque l'option **Démarrer une nouvelle révision lors d'un push** est activée, GitLab Duo démarre automatiquement une révision de suivi lorsque vous poussez des modifications.
