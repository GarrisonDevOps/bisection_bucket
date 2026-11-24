---
title: Automate routine work with scheduled automations (beta)
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
documentation_link: "../../../user/duo_agent_platform/automations/#scheduled-automations"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/24075
categories: [ DAP Triggers ]
level: secondary
---

In previous versions of GitLab, a flow started only when a person or an event kicked it off.
Without one, routine work like issue triage waited.

Now scheduled automations give that work a dependable rhythm. Set the cadence once,
from every 15 minutes to monthly, and a flow runs on its own at the times you choose.
Triage new issues every morning, or check pipeline health every hour.

Each scheduled automation runs as a dedicated service account with a scoped role,
so its actions are attributed to that account, not a person.

Triggers are now called automations. The redesigned **Automations** page brings scheduled
and event-based automations together, with run history, success rates, and session details.

To try it, [turn on experiment and beta features](../../../user/duo_agent_platform/turn_on_off.md#turn-on-beta-and-experimental-features).
