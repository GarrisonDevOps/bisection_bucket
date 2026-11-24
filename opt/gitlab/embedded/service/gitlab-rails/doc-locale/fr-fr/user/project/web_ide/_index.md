---
stage: AI Clients
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Utilisez Web EDI pour modifier plusieurs fichiers dans l'interface GitLab, indexer des commits et créer des merge requests."
title: Web IDE
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/188427) dans GitLab 18.0. Suppression du feature flag `vscode_web_ide`.

{{< /history >}}

Web EDI est un éditeur avancé qui vous permet de modifier plusieurs fichiers, d'indexer des modifications et de créer des commits directement dans l'interface GitLab. Contrairement à [Web Editor](../repository/web_editor.md), Web EDI fournit un environnement de développement complet avec gestion du contrôle de code source.

La prise en charge de l'aperçu [GitLab Flavored Markdown](../../markdown.md) dans Web EDI est proposée dans l'[epic 15810](https://gitlab.com/groups/gitlab-org/-/epics/15810).

## Ouvrir Web EDI {#open-the-web-ide}

Vous pouvez accéder à Web EDI via plusieurs méthodes.

### Avec un raccourci clavier {#with-a-keyboard-shortcut}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Utilisez le raccourci clavier <kbd>.</kbd>.

### Depuis un répertoire {#from-a-directory}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez à votre répertoire.
1. Sélectionnez **Code** > **Ouvrir dans Web EDI**.

### Depuis un fichier {#from-a-file}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez à votre fichier.
1. Sélectionnez **Modifier** > **Ouvrir dans Web EDI**.

### Depuis une merge request {#from-a-merge-request}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Accédez à votre merge request.
1. En haut à droite, sélectionnez **Code** > **Ouvrir dans Web EDI**.

Web EDI ouvre les fichiers nouveaux et modifiés dans des onglets séparés, et affiche les modifications côte à côte. Pour réduire le temps de chargement, seuls les 10 fichiers comportant le plus grand nombre de lignes modifiées s'ouvrent automatiquement.

L'interface de Web EDI affiche une icône de merge request ({{< icon name="merge-request" >}}) à côté des fichiers nouveaux ou modifiés dans la vue **Explorateur** de la barre latérale gauche. Pour afficher les modifications apportées à un fichier, faites un clic droit sur le fichier et sélectionnez **Comparer avec la base de la merge request**.

## Gérer les fichiers {#manage-files}

Vous pouvez utiliser Web EDI pour ouvrir, modifier et téléverser plusieurs fichiers.

### Ouvrir un fichier {#open-a-file}

Pour ouvrir un fichier par nom dans Web EDI :

1. Appuyez sur <kbd>Command</kbd>+<kbd>P</kbd>.
1. Dans la zone de recherche, saisissez le nom du fichier.

### Rechercher dans les fichiers ouverts {#search-open-files}

Pour effectuer une recherche dans les fichiers ouverts dans Web EDI :

1. Appuyez sur <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>F</kbd>.
1. Dans la zone de recherche, saisissez le terme à rechercher.

### Téléverser un fichier {#upload-a-file}

Pour téléverser un fichier dans Web EDI :

1. Sur le côté gauche de Web EDI, sélectionnez **Explorateur** ({{< icon name="documents" >}}), ou appuyez sur <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>E</kbd>.
1. Accédez au répertoire dans lequel vous souhaitez téléverser le fichier. Pour créer un nouveau répertoire :

   - Dans la vue **Explorateur**, en haut à droite, sélectionnez **Nouveau dossier** ({{< icon name="folder-new" >}}).

1. Faites un clic droit sur le répertoire et sélectionnez **Téléversement**.
1. Sélectionnez le fichier que vous souhaitez téléverser.

Vous pouvez téléverser plusieurs fichiers à la fois. Les fichiers sont téléversés et automatiquement ajoutés au dépôt.

### Restaurer les modifications non commitées {#restore-uncommitted-changes}

Vous n'avez pas à sauvegarder manuellement les fichiers que vous modifiez dans Web EDI. Web EDI indexe les fichiers que vous modifiez, afin que vous puissiez [commiter les modifications](#commit-changes). Les modifications non commitées sont enregistrées dans le stockage local de votre navigateur. Elles persistent même si vous fermez l'onglet du navigateur ou actualisez Web EDI.

Si vos modifications non commitées ne sont pas disponibles, vous pouvez les restaurer à partir de l'historique local. Pour restaurer les modifications non commitées dans Web EDI :

1. Appuyez sur <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>P</kbd>.
1. Dans la zone de recherche, saisissez `Local History: Find Entry to Restore`.
1. Sélectionnez le fichier contenant les modifications non commitées.

## Utiliser le contrôle de code source {#use-source-control}

Vous pouvez utiliser le contrôle de code source pour afficher les fichiers modifiés, créer et changer de branche, commiter des modifications et créer des merge requests.

### Afficher les fichiers modifiés {#view-modified-files}

Pour afficher la liste des fichiers que vous avez modifiés dans Web EDI :

- Sur le côté gauche de Web EDI, sélectionnez **Contrôle de code source** ({{< icon name="branch" >}}), ou appuyez sur <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>.

Vos éléments `CHANGES`, `STAGED CHANGES` et `MERGE CHANGES` sont affichés. Pour plus d'informations, consultez la [documentation VS Code](https://code.visualstudio.com/docs/sourcecontrol/overview#_commit).

### Changer de branche {#switch-branches}

Web EDI utilise la branche actuelle par défaut. Pour changer de branche dans Web EDI :

1. Dans la barre de statut inférieure, à gauche, sélectionnez le nom de la branche actuelle.
1. Saisissez ou sélectionnez une branche existante.

### Créer une branche {#create-a-branch}

Pour créer une branche à partir de la branche actuelle dans Web EDI :

1. Dans la barre de statut inférieure, à gauche, sélectionnez le nom de la branche actuelle.
1. Dans la liste déroulante, sélectionnez **Créer une nouvelle branche**.
1. Saisissez le nom de la nouvelle branche.

Web EDI crée une branche en utilisant la branche extraite comme base. Vous pouvez également suivre ces étapes pour créer une branche à partir d'une base différente :

1. Sur le côté gauche de Web EDI, sélectionnez **Contrôle de code source** ({{< icon name="branch" >}}), ou appuyez sur <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>.
1. Sélectionnez le menu représenté par des points de suspension ({{< icon name="ellipsis_h" >}}) en haut à droite du panneau Contrôle de code source.
1. Dans la liste déroulante, sélectionnez **Branche** > **Créer une branche depuis...**.
1. Dans la liste déroulante, sélectionnez la branche que vous souhaitez utiliser comme base.

Si vous ne disposez pas d'un accès en écriture au dépôt, **Créer une nouvelle branche** n'est pas visible.

### Supprimer une branche {#delete-a-branch}

1. Sur le côté gauche de Web EDI, sélectionnez **Contrôle de code source** ({{< icon name="branch" >}}), ou appuyez sur <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>.
1. Sélectionnez le menu représenté par des points de suspension ({{< icon name="ellipsis_h" >}}) en haut à droite du panneau Contrôle de code source.
1. Dans la liste déroulante, sélectionnez **Branche** > **Supprimer cette branche**.
1. Dans la liste déroulante, sélectionnez la branche que vous souhaitez supprimer.

Vous ne pouvez pas supprimer les branches protégées depuis Web EDI.

### Commiter les modifications {#commit-changes}

Pour commiter des modifications dans Web EDI :

1. Sur le côté gauche de Web EDI, sélectionnez **Contrôle de code source** ({{< icon name="branch" >}}), ou appuyez sur <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>.
1. Saisissez votre message de commit.
1. Sélectionnez l'une des options de commit suivantes :
   - **Commiter sur la branche actuelle** \- Commite les modifications sur la branche actuelle
   - **[Créer une nouvelle branche](#create-a-branch)** \- Crée une nouvelle branche et commite les modifications
   - **[Commiter et forcer le push](#commit-and-force-push)** \- Force le push des modifications vers la branche distante
   - **[Modifier le commit et forcer le push](#amend-commit-and-force-push)** \- Modifie le dernier commit et force le push

### Commiter et forcer le push {#commit-and-force-push}

Pour commiter et forcer le push de vos modifications :

1. Sélectionnez le menu du bouton d'action ou sélectionnez les points de suspension ({{< icon name="ellipsis_h" >}}).
1. Sélectionnez **Commiter et forcer le push**.

> [!warning]
> Cette action écrase l'historique distant de la branche actuelle. À utiliser avec précaution.

### Modifier le commit et forcer le push {#amend-commit-and-force-push}

Pour modifier le dernier commit et forcer le push :

1. Sélectionnez le menu du bouton d'action ou sélectionnez les points de suspension ({{< icon name="ellipsis_h" >}}).
1. Sélectionnez **Modifier le commit et forcer le push**.

Cette opération met à jour le dernier commit et force son push vers le dépôt distant. Utilisez cette option pour corriger des commits récents sans en créer de nouveaux.

## Créer une merge request {#create-a-merge-request}

Pour créer une [merge request](../merge_requests/_index.md) dans Web EDI :

1. [Commitez les modifications](#commit-changes).
1. Dans la notification qui apparaît en bas à droite, sélectionnez **Créer une MR**.

Pour plus d'informations, consultez [afficher les notifications manquées](#view-missed-notifications).

## Personnaliser Web EDI {#customize-the-web-ide}

Personnalisez Web EDI selon vos préférences en matière de raccourcis clavier, de thèmes, de paramètres et de synchronisation.

### Utiliser la palette de commandes {#use-the-command-palette}

Vous pouvez utiliser la palette de commandes pour accéder à de nombreuses commandes. Pour ouvrir la palette de commandes et exécuter une commande dans Web EDI :

1. Appuyez sur <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>P</kbd>.
1. Saisissez ou sélectionnez la commande.

### Modifier les paramètres {#edit-settings}

Vous pouvez utiliser l'éditeur de paramètres pour afficher et modifier les paramètres de votre utilisateur et de votre workspace Web EDI. Pour ouvrir l'éditeur de paramètres dans Web EDI :

- Dans la barre de menu supérieure, sélectionnez **Fichier** > **Préférences** > **Paramètres**, ou appuyez sur <kbd>Command</kbd>+<kbd>,</kbd>.

Dans l'éditeur de paramètres, vous pouvez rechercher les paramètres que vous souhaitez modifier.

### Modifier les raccourcis clavier {#edit-keyboard-shortcuts}

Vous pouvez utiliser l'éditeur de raccourcis clavier pour afficher et modifier les raccourcis par défaut pour toutes les commandes disponibles. Pour ouvrir l'éditeur de raccourcis clavier dans Web EDI :

- Dans la barre de menu supérieure, sélectionnez **Fichier** > **Préférences** > **Raccourcis clavier**, ou appuyez sur <kbd>Command</kbd>+<kbd>K</kbd> puis <kbd>Command</kbd>+<kbd>S</kbd>.

Dans l'éditeur de raccourcis clavier, vous pouvez rechercher :

- Les raccourcis que vous souhaitez modifier
- Les commandes pour lesquelles vous souhaitez ajouter ou supprimer des raccourcis

Les raccourcis clavier sont basés sur la disposition de votre clavier. Si vous modifiez la disposition de votre clavier, les raccourcis existants sont mis à jour automatiquement.

### Modifier le thème de couleur {#change-the-color-theme}

Vous pouvez choisir entre différents thèmes de couleur pour Web EDI. Le thème par défaut est **GitLab Dark**.

Pour modifier le thème de couleur dans Web EDI :

1. Dans la barre de menu supérieure, sélectionnez **Fichier** > **Préférences** > **Thème** > **Thème de couleur**, ou appuyez sur <kbd>Command</kbd>+<kbd>K</kbd> puis <kbd>Command</kbd>+<kbd>T</kbd>.
1. Dans la liste déroulante, prévisualisez les thèmes à l'aide des touches fléchées.
1. Sélectionnez un thème.

Web EDI enregistre votre thème de couleur actif dans vos [paramètres utilisateur](#edit-settings).

### Configurer les paramètres de synchronisation {#configure-sync-settings}

Pour configurer les paramètres de synchronisation dans Web EDI :

1. Appuyez sur <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>P</kbd>.
1. Dans la zone de recherche, saisissez `Settings Sync: Configure`.
1. Cochez ou décochez la case pour :
   - **Paramètres**
   - **Raccourcis clavier**
   - **Extraits de code utilisateur**
   - **Tâches utilisateur**
   - **État de l'interface**
   - **Extensions**
   - **Profils**

Ces paramètres se synchronisent automatiquement sur plusieurs instances de Web EDI. Vous ne pouvez pas synchroniser les profils utilisateur ni revenir à une version antérieure des paramètres synchronisés.

### Afficher les notifications manquées {#view-missed-notifications}

Lorsque vous effectuez des actions dans Web EDI, des notifications apparaissent en bas à droite. Pour afficher les notifications que vous avez pu manquer :

1. Dans la barre de statut inférieure, à droite, sélectionnez l'icône de cloche ({{< icon name="notifications" >}}) pour obtenir la liste des notifications.
1. Sélectionnez la notification que vous souhaitez afficher.

## Gérer les extensions {#manage-extensions}

{{< details >}}

- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/151352) en tant que [version bêta](../../../policy/development_stages_support.md#beta) dans GitLab 17.0 [avec des feature flags](../../../administration/feature_flags/_index.md) nommés `web_ide_oauth` et `web_ide_extensions_marketplace`. Fonctionnalité désactivée par défaut.
- `web_ide_oauth` [activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163181) dans GitLab 17.4.
- `web_ide_extensions_marketplace` [activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/459028) dans GitLab 17.4.
- `web_ide_oauth` [supprimé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/167464) dans GitLab 17.5.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/508996) du `vscode_extension_marketplace_settings` [feature flag](../../../administration/feature_flags/_index.md) dans GitLab 17.10. Fonctionnalité désactivée par défaut.
- `web_ide_extensions_marketplace` [activé sur GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662), et `vscode_extension_marketplace_settings` [activé sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662) dans GitLab 17.11.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192659) dans GitLab 18.1. Les feature flags `web_ide_extensions_marketplace` et `vscode_extension_marketplace_settings` ont été supprimés.

{{< /history >}}

Le VS Code Extension Marketplace donne accès à des extensions qui améliorent les fonctionnalités de Web EDI. Par défaut, Web EDI de GitLab se connecte à l'[Open VSX Registry](https://open-vsx.org/).

> [!note]
> Pour accéder au VS Code Extension Marketplace, votre navigateur doit pouvoir accéder à l'hôte d'assets `.cdn.web-ide.gitlab-static.net`. Cette exigence de sécurité garantit que les extensions tierces s'exécutent de manière isolée et ne peuvent pas accéder à votre compte. Cela s'applique à la fois à GitLab.com et à GitLab Self-Managed.

Prérequis :

- Vous devez [intégrer le marketplace d'extensions](../../profile/preferences.md#integrate-with-the-extension-marketplace) dans vos préférences utilisateur.
- Pour GitLab Self-Managed et GitLab Dedicated, un administrateur GitLab doit [activer le registre d'extensions](../../../administration/settings/vscode_extension_marketplace.md).
- Pour les utilisateurs d'entreprise, un propriétaire de groupe doit [activer le marketplace d'extensions pour les utilisateurs d'entreprise](../../enterprise_user/_index.md#enable-the-extension-marketplace-for-enterprise-users).

### Installer une extension {#install-an-extension}

Pour installer une extension dans Web EDI :

1. Dans la barre de menu supérieure, sélectionnez **Afficher** > **Extensions**, ou appuyez sur <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>X</kbd>.
1. Dans la zone de recherche, saisissez le nom de l'extension.
1. Sélectionnez l'extension que vous souhaitez installer.
1. Sélectionnez **Installer**.

### Désinstaller une extension {#uninstall-an-extension}

Pour désinstaller une extension dans Web EDI :

1. Dans la barre de menu supérieure, sélectionnez **Afficher** > **Extensions**, ou appuyez sur <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>X</kbd>.
1. Dans la liste des extensions installées, sélectionnez l'extension que vous souhaitez désinstaller.
1. Sélectionnez **Désinstaller**.

### Configuration des extensions {#extension-setup}

Les extensions Web EDI peuvent nécessiter une configuration supplémentaire pour fonctionner avec vos projets.

#### Utiliser les raccourcis clavier Vim {#use-vim-keybindings}

Utilisez les raccourcis clavier Vim pour naviguer et modifier du texte à l'aide des raccourcis clavier de l'éditeur de texte Vim. Grâce au marketplace d'extensions, vous pouvez ajouter les raccourcis clavier Vim à Web EDI.

Pour activer les raccourcis clavier Vim, installez l'extension [Vim](https://open-vsx.org/extension/vscodevim/vim). Pour plus d'informations, consultez [installer une extension](#install-an-extension).

#### Prise en charge d'AsciiDoc {#asciidoc-support}

L'extension [AsciiDoc](https://open-vsx.org/extension/asciidoctor/asciidoctor-vscode) fournit un aperçu en direct, la coloration syntaxique et des extraits de code pour les fichiers AsciiDoc dans Web EDI. Pour utiliser l'aperçu du balisage AsciiDoc dans Web EDI, vous devez installer l'extension AsciiDoc. Pour plus d'informations, consultez [installer une extension](#install-an-extension).

## Sujets connexes {#related-topics}

- [GitLab Duo Non-Agentic Chat dans Web EDI](../../gitlab_duo_chat/_index.md#use-gitlab-duo-chat-in-the-web-ide)

## Dépannage {#troubleshooting}

Lors de l'utilisation de Web EDI, vous pouvez rencontrer les problèmes suivants.

### Décalage de caractères lors de la saisie {#character-offset-when-typing}

Lorsque vous tapez dans Web EDI, vous pouvez obtenir un décalage de quatre caractères. Pour contourner ce problème :

1. Dans la barre de menu supérieure, sélectionnez **Fichier** > **Préférences** > **Paramètres**, ou appuyez sur <kbd>Command</kbd>+<kbd>,</kbd>.
1. Dans le coin supérieur droit, sélectionnez **Ouvrir les paramètres (JSON)**.
1. Dans le fichier `settings.json`, ajoutez `"editor.disableMonospaceOptimizations": true` ou modifiez le paramètre `"editor.fontFamily"`.

Pour plus d'informations, consultez le [problème VS Code 80170](https://github.com/microsoft/vscode/issues/80170).

### Mettre à jour l'URL de rappel OAuth {#update-the-oauth-callback-url}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.

Web EDI utilise une [application OAuth à l'échelle de l'instance](../../../integration/oauth_provider.md#create-an-instance-wide-application) pour l'authentification. Si l'URL de rappel OAuth est mal configurée, vous pouvez rencontrer une page d'erreur `Cannot open Web IDE` avec le message suivant :

```plaintext
The URL you're using to access the Web IDE and the configured OAuth callback URL do not match. This issue often occurs when you're using a proxy.
```

Pour résoudre ce problème, vous devez mettre à jour l'URL de rappel OAuth afin qu'elle corresponde à l'URL utilisée pour accéder à l'instance GitLab.

Prérequis :

- Disposer d'un accès administrateur.

Pour mettre à jour l'URL de rappel OAuth :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Applications**.
1. Pour **GitLab Web IDE**, sélectionnez **Modifier**.
1. Saisissez l'URL de rappel OAuth. Vous pouvez saisir plusieurs URL séparées par des sauts de ligne.

### La durée de vie du jeton d'accès ne peut pas être inférieure à 5 minutes {#access-token-lifetime-cannot-be-less-than-5-minutes}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

Vous pouvez rencontrer un message d'erreur indiquant que la durée de vie du jeton d'accès ne peut pas être inférieure à 5 minutes.

Cette erreur se produit lorsque votre instance GitLab est configurée avec un délai d'expiration du jeton d'accès inférieur à 5 minutes. Web EDI nécessite des jetons d'accès avec une durée de vie minimale de 5 minutes pour fonctionner correctement.

Pour résoudre ce problème, augmentez la durée de vie du jeton d'accès à au moins 5 minutes dans la configuration de votre instance. Pour plus d'informations sur la configuration de l'expiration des jetons d'accès, consultez [expiration des jetons d'accès](../../../integration/oauth_provider.md#access-token-expiration).

### Dépendance Workhorse {#workhorse-dependency}

{{< details >}}

- Offre : GitLab Self-Managed

{{< /details >}}

Sur GitLab Self-Managed, Workhorse doit être installé et s'exécuter en frontal du serveur GitLab Rails. Dans le cas contraire, vous pouvez rencontrer des problèmes lorsque vous ouvrez Web EDI ou utilisez certaines fonctionnalités telles que l'aperçu Markdown.

Pour des raisons de sécurité, certaines parties de Web EDI doivent s'exécuter sur une origine distincte. Pour prendre en charge cette approche, Web EDI utilise Workhorse pour acheminer les requêtes de manière appropriée vers et depuis les assets de Web EDI. Les assets de Web EDI sont des assets frontend statiques ; il est donc inutile de solliciter Rails pour cela.

### Problèmes CORS {#cors-issues}

Web EDI nécessite une configuration spécifique du partage des ressources entre origines (CORS) pour fonctionner correctement sur les instances GitLab Self-Managed. Les points de terminaison de l'API GitLab (`/api/*`) doivent inclure les en-têtes de réponse HTTP suivants pour prendre en charge Web EDI :

| En-tête | Valeur | Description |
|--------|-------|-------------|
| `Access-Control-Allow-Origin` | `https://[subdomain].cdn.web-ide.gitlab-static.net` | Autorise les requêtes provenant de l'origine de Web EDI. Le `[subdomain]` est une chaîne alphanumérique générée dynamiquement (52 caractères maximum). |
| `Access-Control-Allow-Headers` | `Authorization` | Autorise l'en-tête Authorization dans les requêtes cross-origin. |
| `Access-Control-Allow-Methods` | `GET, POST, PUT, DELETE, OPTIONS` | Spécifie les méthodes HTTP autorisées (recommandé). |
| `Access-Control-Allow-Credentials` | `false` | Web EDI n'a pas besoin d'inclure les identifiants contrôlés par cet [en-tête](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Credentials) dans les requêtes HTTP. |
| `Access-Control-Expose-Headers` | `Link, X-Total, X-Total-Pages, X-Per-Page, X-Page, X-Next-Page, X-Prev-Page, X-Gitlab-Blob-Id, X-Gitlab-Commit-Id, X-Gitlab-Content-Sha256, X-Gitlab-Encoding, X-Gitlab-File-Name, X-Gitlab-File-Path, X-Gitlab-Last-Commit-Id X-Gitlab-Ref, X-Gitlab-Size, X-Request-Id, ETag, X-Streaming-Format` | En-têtes utilisés par les API REST et GraphQL de GitLab. |
| `Vary` | `Origin` | Garantit un comportement de mise en cache approprié pour les réponses CORS. |

Web EDI génère dynamiquement la partie sous-domaine du domaine hôte de l'extension. Assurez-vous que les en-têtes CORS respectent les règles suivantes :

- **Correspondance de pattern** : acceptez les origines correspondant au pattern `https://*.cdn.web-ide.gitlab-static.net`.
- **Validation** :  assurez-vous que le sous-domaine ne contient que des caractères alphanumériques et ne dépasse pas 52 caractères.
- **Sécurité** :  n'utilisez jamais le caractère générique (`*`) pour Access-Control-Allow-Origin, car cela présente des risques de sécurité.

La configuration CORS par défaut d'une instance GitLab satisfait à ces exigences. Vous pouvez rencontrer des problèmes lorsque l'instance GitLab Self-Managed se trouve derrière un serveur proxy inverse HTTP ou utilise une configuration de politique CORS personnalisée.

### Environnements hors ligne {#offline-environments}

Web EDI dispose de fonctionnalités limitées lorsqu'il ne peut pas se connecter au domaine hôte d'extension par défaut (`https://*.cdn.web-ide.gitlab-static.net`). Dans les environnements hors ligne, les administrateurs GitLab peuvent configurer un [domaine hôte d'extension personnalisé](../../../administration/settings/web_ide.md) comme solution de contournement.

### Signaler un problème {#report-a-problem}

Pour signaler un problème, [créez un nouveau ticket](https://gitlab.com/gitlab-org/gitlab-web-ide/-/issues/new) avec les informations suivantes :

- Le message d'erreur
- Les détails complets de l'erreur
- La fréquence à laquelle le problème se produit
- Les étapes pour reproduire le problème

Si vous utilisez une édition payante, vous pouvez également [contacter le support](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#contact-support) pour obtenir de l'aide.
