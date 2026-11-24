---
title: "Autres ajouts à l'interface"
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
co_create: true
documentation_link: "../../../user/project/merge_requests/approvals/"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258534
categories: [ Code Review Workflow ]
level: secondary
weight: 90
---

Cette release inclut également les ajouts suivants à l'interface :

- La modification de **Approbation requise** dans les paramètres de la merge request affiche un toast en cas de succès et une alerte en cas d'échec.
- Un framework de conformité dont l'exigence comporte déjà 5 contrôles peut à nouveau être modifié.
- La mise à jour échouée d'un environnement protégé affiche le message de l'API.
- Dans la boîte de dialogue **Créer une branche**, le bouton d'envoi reste désactivé jusqu'à ce que le nom de la branche soit validé.
- Les labels archivés affichent une info-bulle **Archivées** dans les listes de tickets et de merge requests, et ne peuvent pas être nouvellement assignés.
- Les tokens SCIM ne peuvent pas être générés lorsque le fournisseur SAML du groupe est désactivé.
- La coloration syntaxique est appliquée aux fichiers `.4dm`.
- Les colonnes de tableau Markdown alignées à droite utilisent des chiffres à largeur fixe.

Les règles d'approbation, les frameworks de conformité et les environnements protégés nécessitent GitLab Premium ou GitLab Ultimate.

Merci aux utilisateurs suivants pour leurs contributions !

- [Sahil Bhatt](https://gitlab.com/Sahil8383) ([MR 1](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258534) [MR 2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/258009))
- [Jeston Singh](https://gitlab.com/sjestonsingh) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255147))
- [Vladislav Petrov](https://gitlab.com/plus3x) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256907))
- [Nicholas Wittstruck](https://gitlab.com/nwittstruck) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251069))
- [ryo-whaletech](https://gitlab.com/ryo-whaletech) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255219))
- [Sergey Pechenko](https://gitlab.com/tnt4brain) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249242))
- [Logan Swartzendruber](https://gitlab.com/loganswartz) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257688))
- [Steve Mokris](https://gitlab.com/smokris) ([MR](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254031))
