---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Les projets GitLab affichent les fichiers Jupyter Notebook sous forme de fichiers lisibles et clairs plutôt que de fichiers bruts.
title: Fichiers Jupyter Notebook
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les fichiers [Jupyter Notebook](https://jupyter.org/) (anciennement IPython Notebook) sont utilisés pour le calcul interactif dans de nombreux domaines. Ils contiennent un enregistrement complet des sessions de l'utilisateur et comprennent :

- Du code.
- Du texte narratif.
- Des équations.
- Des sorties enrichies.

Lorsque vous ajoutez un fichier Jupyter Notebook (avec l'extension `.ipynb`) à votre dépôt, il est rendu en HTML lorsque vous le consultez :

![Sortie enrichie Jupyter Notebook](img/jupyter_notebook_v17_10.png)

Les fonctionnalités interactives, notamment les graphiques JavaScript, ne fonctionnent pas lorsqu'elles sont affichées dans GitLab.

## Diffs plus lisibles et diffs bruts {#cleaner-diffs-and-raw-diffs}

Lorsque des commits incluent des modifications apportées à des fichiers Jupyter Notebook, GitLab :

- Transforme le fichier `.ipynb` lisible par machine en fichier Markdown lisible par l'utilisateur.
- Affiche une version plus lisible du diff incluant la coloration syntaxique.
- Permet de basculer entre les diffs bruts et les diffs rendus sur les pages Commit et Comparer. (Non disponible sur les pages de merge request.)
- Affiche les images dans les diffs.

Code Suggestions n'est pas disponible dans les diffs et les merge requests pour les fichiers `.ipynb`.

Les diffs de notebook plus lisibles ne sont pas générés lorsque le notebook est trop volumineux.

## Intégration Git de Jupyter {#jupyter-git-integration}

Jupyter peut être configuré en tant qu'application OAuth avec accès au dépôt, agissant au nom de l'utilisateur authentifié. Pour un exemple de configuration, consultez les [runbooks](../../../clusters/runbooks/_index.md).
