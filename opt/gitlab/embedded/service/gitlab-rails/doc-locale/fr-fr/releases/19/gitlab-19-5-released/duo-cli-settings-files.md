---
title: "Configurer GitLab Duo CLI avec des fichiers de paramètres"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/settings/"
work_item: https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2126
categories: [ Duo CLI ]
level: secondary
weight: 50
---

Vous pouvez désormais configurer GitLab Duo CLI avec des fichiers de paramètres, pour vous-même ou pour l'ensemble de votre organisation.

Le fichier de paramètres enregistre les choix que vous effectuez dans le panneau `/settings`. Vous pouvez également modifier le fichier directement, ou le créer à l'avance, par exemple dans une image de conteneur.

Les administrateurs système peuvent déployer un fichier de paramètres géré sur chaque machine à l'aide d'un outil de gestion des appareils mobiles ou d'une stratégie de groupe. Les paramètres du fichier géré ont la priorité sur le fichier de paramètres, les options de ligne de commande et les variables d'environnement, et les utilisateurs ne peuvent pas les modifier. Les paramètres qui ne figurent pas dans le fichier géré restent sous le contrôle des utilisateurs.

Le fichier de paramètres nécessite GitLab Duo CLI 9.26.0 ou une version ultérieure, et le fichier de paramètres géré nécessite GitLab Duo CLI 9.27.0 ou une version ultérieure.
