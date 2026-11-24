---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "La coloration syntaxique vous aide à lire les fichiers de votre projet GitLab et à identifier ce qu'ils contiennent."
title: Coloration syntaxique
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab fournit la coloration syntaxique pour les fichiers via deux systèmes complémentaires :

- [Rouge](https://rubygems.org/gems/rouge) (gem Ruby) : coloration côté serveur qui traite les fichiers sur les serveurs GitLab. Il est utilisé pour :
  - Affichage des fichiers du dépôt
  - Diffs des merge requests
  - Diffs de commit
  - Vue de comparaison
  - Vue Blame
- [Highlight.js](https://github.com/highlightjs/highlight.js/) : coloration côté client qui s'exécute dans votre navigateur. Il est utilisé pour afficher les fichiers du dépôt dans le navigateur pour les langages pris en charge.

Les chemins indiqués ici utilisent l'[interface `.gitattributes`](https://git-scm.com/docs/gitattributes) dans Git.

> [!note]
> Le [Web IDE](../../web_ide/_index.md) et les [snippets](../../../snippets.md) utilisent l'[éditeur Monaco](https://microsoft.github.io/monaco-editor/) pour l'édition de texte, qui utilise en interne la [bibliothèque Monarch](https://microsoft.github.io/monaco-editor/monarch.html) pour la coloration syntaxique.

## Remplacer la coloration syntaxique pour un type de fichier {#override-syntax-highlighting-for-a-file-type}

> [!note]
> Le Web IDE ne prend pas en charge les fichiers `.gitattributes`. Pour plus d'informations, consultez l'[epic 18651](https://gitlab.com/groups/gitlab-org/-/work_items/18651).

Pour remplacer la coloration syntaxique pour un type de fichier :

1. Si un fichier `.gitattributes` n'existe pas dans le répertoire racine de votre projet, créez un fichier vide avec ce nom.
1. Pour chaque type de fichier que vous souhaitez modifier, ajoutez une ligne au fichier `.gitattributes` en déclarant l'extension de fichier et le langage de coloration souhaité :

   ```conf
   # This extension typically receives Perl syntax highlighting. If you
   # also use Prolog, you can override highlighting for this file extension:
   *.pl gitlab-language=prolog
   ```

1. Effectuez un commit, un push et fusionnez vos modifications dans votre branche par défaut.

Une fois les modifications fusionnées dans votre [branche par défaut](../branches/default.md), tous les fichiers `*.pl` de votre projet sont colorés dans le langage de votre choix.

Vous pouvez également étendre la coloration avec des options Common Gateway Interface (CGI), telles que :

``` conf
# JSON file with .erb in it
/my-cool-file gitlab-language=erb?parent=json

# An entire file of highlighting errors!
/other-file gitlab-language=text?token=Error
```

## Désactiver la coloration syntaxique pour un type de fichier {#disable-syntax-highlighting-for-a-file-type}

Pour désactiver entièrement la coloration pour un type de fichier, suivez les instructions pour remplacer la coloration pour un type de fichier et utilisez `gitlab-language=text` :

```conf
# Disable syntax highlighting for this file type
*.module gitlab-language=text
```

## Configurer la taille maximale de fichier pour la coloration {#configure-maximum-file-size-for-highlighting}

Les limites de taille de fichier suivantes s'appliquent aux outils de coloration syntaxique :

- Rouge (côté serveur) : 512 Ko par défaut (configurable)
  - Les fichiers dépassant cette limite sont affichés en texte brut sans coloration syntaxique.
- Highlight.js (côté client) : 2 Mo (non configurable)
  - Revient à la coloration Rouge si un langage n'est pas pris en charge.
  - Les fichiers dépassant cette limite ne peuvent pas être colorés dans le frontend et doivent être consultés en tant que contenu brut.

Pour modifier la limite de coloration Rouge :

1. Ouvrez le fichier de configuration [`gitlab.yml`](https://gitlab.com/gitlab-org/gitlab-foss/blob/master/config/gitlab.yml.example) de votre projet.

1. Ajoutez cette section en remplaçant `maximum_text_highlight_size_kilobytes` par la valeur souhaitée.

   ```yaml
   gitlab:
     extra:
       ## Maximum file size for syntax highlighting
       ## https://docs.gitlab.com/user/project/repository/files/highlighting/#configure-maximum-file-size-for-highlighting
       maximum_text_highlight_size_kilobytes: 512
   ```

1. Effectuez un commit, un push et fusionnez vos modifications dans votre branche par défaut.
