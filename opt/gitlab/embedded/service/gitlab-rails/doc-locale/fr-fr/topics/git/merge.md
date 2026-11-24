---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Fusionner votre branche avec la branche principale
---

Après avoir [créé une branche](branch.md), effectué les modifications requises et [les avoir committées localement](commit.md), vous [poussez votre branche](commit.md#send-changes-to-gitlab) et ses commits vers GitLab.

En réponse à la commande `git push`, GitLab fournit un lien direct pour créer la merge request. Par exemple :

```plaintext
...
remote: To create a merge request for my-new-branch, visit:
remote:   https://gitlab.example.com/my-group/my-project/merge_requests/new?merge_request%5Bsource_branch%5D=my-new-branch
```

Pour fusionner votre branche avec la branche principale :

1. Accédez à la page fournie dans le lien indiqué par Git et [créez votre merge request](../../user/project/merge_requests/creating_merge_requests.md). La **Branche source** de la merge request est votre branche et la **Branche cible** doit être la branche principale.
1. Si nécessaire, faites [réviser votre merge request](../../user/project/merge_requests/reviews/_index.md#request-a-review).
1. Demandez à quelqu'un de [fusionner votre merge request](../../user/project/merge_requests/_index.md#merge-a-merge-request), ou fusionnez-la vous-même, selon votre processus.

## Sujets connexes {#related-topics}

- [Merge requests](../../user/project/merge_requests/_index.md)
- [Méthodes de fusion](../../user/project/merge_requests/methods/_index.md)
- [Conflits de merge](../../user/project/merge_requests/conflicts.md)
