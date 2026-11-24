---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Définissez des attributs Git personnalisés pour votre projet GitLab afin de configurer les options de gestion des fichiers, d'affichage, de verrouillage et de stockage."
title: Attributs Git
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab prend en charge la définition d'attributs Git personnalisés dans un fichier `.gitattributes` dans le répertoire racine de votre dépôt. Utilisez le fichier `.gitattributes` pour déclarer des modifications relatives à la gestion et à l'affichage des fichiers, par exemple :

- [Réduire les fichiers générés](../../merge_requests/changes.md#collapse-generated-files) dans les diffs.
- Créer des [pilotes de merge personnalisés](#custom-merge-drivers).
- Créer des [fichiers de verrouillage exclusifs](../../file_lock.md) pour marquer les fichiers en lecture seule.
- Modifier la [coloration syntaxique](highlighting.md) dans les diffs.
- Déclarer la gestion des fichiers binaires avec [Git LFS](../../../../topics/git/lfs/_index.md).
- Déclarer les [langages utilisés dans votre dépôt](../_index.md#add-repository-languages).

## Exigences d'encodage {#encoding-requirements}

Le fichier `.gitattributes` doit être encodé en UTF-8 et ne doit pas contenir de marque d'ordre d'octet (BOM). Si un encodage différent est utilisé, le contenu du fichier est ignoré.

## Prise en charge des encodages de fichiers mixtes {#support-for-mixed-file-encodings}

GitLab tente de détecter automatiquement l'encodage des fichiers, mais utilise par défaut UTF-8, sauf si le détecteur est certain d'un type différent (tel que `ISO-8859-1`). Une détection d'encodage incorrecte peut entraîner l'absence d'affichage de certains caractères dans le texte, comme les caractères accentués dans un encodage non-UTF-8.

Git intègre une prise en charge native de cette situation et convertit automatiquement les fichiers entre un encodage désigné et UTF-8 pour le dépôt lui-même. Configurez la prise en charge des encodages de fichiers mixtes dans le fichier `.gitattributes` à l'aide de l'attribut `working-tree-encoding`.

Exemple :

```plaintext
*.xhtml text working-tree-encoding=ISO-8859-1
```

Avec cet exemple de configuration, Git conserve tous les fichiers `.xhtml` du dépôt en encodage ISO-8859-1 dans l'arborescence locale, mais effectue les conversions vers et depuis UTF-8 lors des commits dans le dépôt. GitLab affiche les fichiers avec précision, car il ne voit que de l'UTF-8 correctement encodé.

Si vous appliquez cette configuration à un dépôt existant, il peut être nécessaire de modifier et de recommitter les fichiers si la copie locale possède l'encodage correct, mais pas le dépôt. Cette opération peut être effectuée pour l'ensemble du dépôt en exécutant `git add --renormalize .`.

Pour plus d'informations, consultez [working-tree-encoding](https://git-scm.com/docs/gitattributes#_working_tree_encoding).

## Coloration syntaxique {#syntax-highlighting}

Le fichier `.gitattributes` peut être utilisé pour définir le langage à utiliser lors de la coloration syntaxique des fichiers et des diffs. Pour plus d'informations, consultez [la coloration syntaxique](highlighting.md).

## Pilotes de merge personnalisés {#custom-merge-drivers}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les administrateurs GitLab Self-Managed peuvent définir des [pilotes de merge personnalisés](https://git-scm.com/docs/gitattributes#_defining_a_custom_merge_driver) dans un fichier de configuration GitLab, puis utiliser ces pilotes de merge personnalisés dans un fichier Git `.gitattributes`. Les pilotes de merge personnalisés ne sont pas pris en charge sur GitLab.com.

Les pilotes de merge personnalisés sont une fonctionnalité Git qui vous offre un contrôle avancé sur la résolution des conflits. Un pilote de merge personnalisé n'est invoqué qu'en cas de [conflit de merge](../../merge_requests/conflicts.md) non trivial ; il ne constitue donc pas un moyen fiable d'empêcher le merge de certains fichiers.

### Configurer un pilote de merge personnalisé {#configure-a-custom-merge-driver}

L'exemple suivant illustre comment définir et utiliser un pilote de merge personnalisé dans GitLab.

La façon de configurer un pilote de merge personnalisé dépend du type d'installation.

{{< tabs >}}

{{< tab title="Paquet Linux (Omnibus)" >}}

1. Modifiez `/etc/gitlab/gitlab.rb`.
1. Ajoutez une configuration similaire à la suivante :

   ```ruby
   gitaly['configuration'] = {
     # ...
     git: {
       # ...
       config: [
         # ...
         { key: "merge.foo.driver", value: "true" },
       ],
     },
   }
   ```

{{< /tab >}}

{{< tab title="Auto-compilée (source)" >}}

1. Modifiez `gitaly.toml`.
1. Ajoutez une configuration similaire à la suivante :

   ```toml
   [[git.config]]
   key = "merge.foo.driver"
   value = "true"
   ```

{{< /tab >}}

{{< /tabs >}}

Dans cet exemple, lors d'un merge, Git utilise la valeur `driver` comme commande à exécuter. Étant donné que l'exemple utilise [`true`](https://man7.org/linux/man-pages/man1/true.1.html) sans argument, il renvoie toujours un code de retour non nul. Cela signifie que, pour les fichiers spécifiés dans `.gitattributes`, les merges n'ont aucun effet.

Pour utiliser votre propre pilote de merge, remplacez la valeur dans `driver` pour pointer vers un exécutable. Pour plus de détails sur la façon dont cette commande est invoquée, consultez la documentation Git sur les [pilotes de merge personnalisés](https://git-scm.com/docs/gitattributes#_defining_a_custom_merge_driver).

### Utiliser `.gitattributes` pour définir les fichiers auxquels le pilote de merge personnalisé s'applique {#use-gitattributes-to-set-files-custom-merge-driver-applies-to}

Dans un fichier `.gitattributes`, vous pouvez définir les chemins des fichiers que vous souhaitez utiliser avec le pilote de merge personnalisé. Par exemple :

```plaintext
config/* merge=foo
```

Dans ce cas, chaque fichier du dossier `config/` utilise le pilote de merge personnalisé appelé `foo` défini dans la configuration GitLab.

## Ressources {#resources}

- Documentation Git officielle sur les [attributs Git](https://git-scm.com/docs/gitattributes)
