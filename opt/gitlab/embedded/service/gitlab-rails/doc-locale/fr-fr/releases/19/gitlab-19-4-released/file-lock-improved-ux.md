---
title: Voir qui a verrouillé un fichier ou un répertoire
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: create
documentation_link: "../../../user/project/file_lock"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/13019
categories: [ Source Code Management ]
level: secondary
weight: 50
---

Lorsqu'un fichier est verrouillé, vous voyez désormais qui l'a verrouillé et quelles sont vos options, sans quitter la visionneuse de blob.

Auparavant, seul un label **Verrouillé** apparaissait, sans aucun moyen de savoir qui avait verrouillé le fichier ni si vous pouviez le déverrouiller vous-même. Désormais, une fenêtre contextuelle affichée à côté du label indique qui l'a verrouillé. Si vous avez l'autorisation de déverrouiller le fichier, la fenêtre contextuelle inclut une action de déverrouillage. Dans le cas contraire, elle explique pourquoi. Pour les répertoires verrouillés, la fenêtre contextuelle vous redirige directement vers le fichier spécifique qui bloque vos modifications.
