---
title: "Provide images as context with self-hosted models"
tier: [ Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated_for_government ]
stage: agent_foundations
documentation_link: "../../../administration/gitlab_duo_self_hosted/configure_duo_features/#declare-image-support-for-a-self-hosted-model"
work_item: https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/work_items/3335
categories: [ Duo Developer ]
level: secondary
weight: 50
---

In previous versions of GitLab, the Developer Flow and Agentic Chat did not support images as context
with self-hosted models.

Now, they can read screenshots and diagrams from your repository and attachments with any self-hosted
model that supports image input.

If your model cannot read images, an administrator can declare it in the AI Gateway model metadata file.
The AI Gateway then replaces each image with a text notice before it sends the request.
