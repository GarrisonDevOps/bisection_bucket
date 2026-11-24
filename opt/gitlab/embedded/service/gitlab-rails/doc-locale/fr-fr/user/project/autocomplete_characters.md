---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Caractères d'autocomplétion dans les champs Markdown."
title: "Caractères d'autocomplétion"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les caractères d'autocomplétion permettent de saisir rapidement des valeurs dans les champs Markdown. Lorsque vous commencez à saisir un mot dans un champ Markdown avec l'un des caractères suivants, GitLab propose progressivement une autocomplétion parmi un ensemble de valeurs correspondantes. La correspondance de chaîne n'est pas sensible à la casse.

| Caractère | Autocomplétion    | Correspondances pertinentes affichées |
| --------- | ---------------- | ---------------------- |
| `~`       | Labels           | 20                     |
| `%`       | Les jalons       | 5                      |
| `@`       | Utilisateurs et groupes | 10                     |
| `#`       | Les tickets           | 5                      |
| `!`       | Les merge requests   | 5                      |
| `&`       | Les epics            | 5                      |
| `$`       | les snippets ;         | 5                      |
| `:`       | Émoji            | 5                      |
| `/`       | Actions rapides    | 100                    |
| `*iteration:` | Itérations | 5 |

Lorsque vous sélectionnez un élément dans la liste, la valeur est saisie dans le champ. Plus vous saisissez de caractères, plus les correspondances sont précises.

Vous pouvez utiliser des caractères d'autocomplétion en combinaison avec les [actions rapides](quick_actions.md).

## Autocomplétion des utilisateurs {#user-autocomplete}

Supposons que votre instance GitLab inclut les utilisateurs suivants :

<!-- vale gitlab_base.Spelling = NO -->

| Nom d'utilisateur        | Nom |
| :-------------- | :--- |
| alessandra      | Rosy Grant |
| lawrence.white  | Kelsey Kerluke |
| leanna          | Rosemarie Rogahn |
| logan_gutkowski | Lee Wuckert |
| shelba          | Josefine Haley |

<!-- vale gitlab_base.Spelling = YES -->

L'autocomplétion des utilisateurs trie en priorité les utilisateurs dont le nom d'utilisateur ou le nom commence par votre requête. Par exemple, saisir `@lea` affiche d'abord `leanna`, et saisir `@ros` affiche d'abord `Rosemarie Rogahn` et `Rosy Grant`. Les noms d'utilisateur ou noms qui contiennent votre requête sont affichés ensuite dans le menu d'autocomplétion.

Vous pouvez également effectuer une recherche sur le nom complet pour trouver un utilisateur. Pour trouver `Rosy Grant`, même si son nom d'utilisateur est par exemple `alessandra`, vous pouvez saisir son nom complet sans espaces, comme `@rosygrant`.
