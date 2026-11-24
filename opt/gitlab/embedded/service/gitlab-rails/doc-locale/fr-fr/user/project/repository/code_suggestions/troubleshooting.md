---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Conseils de dépannage pour les problèmes courants dans Code Suggestions.
title: Dépannage de Code Suggestions
---

Lorsque vous utilisez GitLab Duo Code Suggestions, vous pouvez rencontrer les problèmes suivants.

Vous pouvez exécuter un [bilan de santé](../../../gitlab_duo/turn_on_off.md) pour vérifier si votre instance répond aux exigences nécessaires à l'exécution de Code Suggestions.

Pour plus d'informations sur le dépannage de GitLab Duo, consultez :

- [Dépannage de GitLab Duo](../../../gitlab_duo/troubleshooting.md).
- [Dépannage de GitLab Duo Chat](../../../gitlab_duo_chat/troubleshooting.md).
- [Dépannage de GitLab Duo Self-Hosted](../../../../administration/gitlab_duo_self_hosted/troubleshooting.md).

## Les suggestions ne s'affichent pas {#suggestions-are-not-displayed}

Si les suggestions ne s'affichent pas, vérifiez que vous :

- Avez [configuré GitLab Duo correctement](../../../gitlab_duo/turn_on_off.md).
- Utilisez un [langage pris en charge](supported_extensions.md#supported-languages-by-ide) et une [extension d'éditeur](supported_extensions.md#supported-editor-extensions).
- Avez [configuré votre extension d'éditeur correctement](set_up.md#configure-an-editor-extension).

Si les suggestions ne s'affichent toujours pas, essayez les étapes de dépannage suivantes pour les différents IDE :

- [VS Code ou GitLab Web IDE](#suggestions-not-displayed-in-vs-code-or-gitlab-web-ide)
- [IDE JetBrains](#suggestions-not-displayed-in-jetbrains-ides)
- [Microsoft Visual Studio](#suggestions-not-displayed-in-microsoft-visual-studio)

## Code Suggestions renvoie une erreur 401 {#code-suggestions-returns-a-401-error}

Code Suggestions dépend d'un jeton de licence qui [synchronise votre abonnement](../../../../administration/license.md) avec GitLab.

Lorsque le jeton expire, Code Suggestions renvoie l'erreur suivante avec le statut `401` :

```plaintext
Token validation failed in Language Server:
(Failed to check token: Error: Fetching Information about personal access token
```

Si GitLab a accès au serveur cloud, essayez de [synchroniser manuellement votre licence](../../../../subscriptions/manage_subscription.md#manually-synchronize-subscription-data).

## Dépannage de l'authentification {#authentication-troubleshooting}

Le problème peut être lié aux modifications récentes apportées à l'authentification, notamment au système de jetons. Pour résoudre le problème :

1. Supprimez le jeton d'accès personnel existant dans les paramètres de votre compte GitLab.
1. Réautorisez votre compte GitLab via OAuth.
1. Testez la fonctionnalité Code Suggestions avec différentes extensions de fichier pour vérifier si le problème est résolu.

## Erreur 422 : Aucun espace de nommage GitLab Duo par défaut {#error-422-no-default-gitlab-duo-namespace}

Vous pouvez obtenir une erreur indiquant `Code Suggestions cannot detect a namespace for this project. To continue, please set a default GitLab Duo namespace in your user preferences.`

Ce problème se produit lorsque vous appartenez à plusieurs espaces de nommage GitLab Duo ou que vous travaillez localement sur un projet qui ne possède aucun dépôt distant GitLab configuré.

Pour résoudre ce problème, [définissez un espace de nommage GitLab Duo par défaut](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace).

## Dépannage de VS Code {#vs-code-troubleshooting}

La documentation suivante concerne le dépannage spécifique à Code Suggestions pour VS Code.

Pour tout autre dépannage de GitLab pour VS Code, consultez [le dépannage de l'extension GitLab pour VS Code](../../../../editor_extensions/visual_studio_code/troubleshooting.md).

### Suggestions non affichées dans VS Code ou GitLab Web IDE {#suggestions-not-displayed-in-vs-code-or-gitlab-web-ide}

Si vous utilisez GitLab Self-Managed, vérifiez que Code Suggestions pour [GitLab Web IDE](../../web_ide/_index.md) est activé. Les mêmes paramètres s'appliquent à VS Code en tant qu'IDE local.

1. Dans votre IDE, ouvrez l'éditeur de paramètres :
   - Pour macOS, appuyez sur <kbd>Commande</kbd>+<kbd>,</kbd>.
   - Pour Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>,</kbd>.
1. Accédez aux paramètres **GitLab Duo** :
   - Dans VS Code, sélectionnez **Extensions** > **GitLab** > **GitLab Duo**.
   - Dans GitLab Web IDE, sélectionnez **Extensions** > **GitLab Workflow** > **GitLab Duo**.
1. Sous **GitLab › Duo Code Suggestions : activé**, cochez la case.

#### Afficher les journaux de Code Suggestions {#view-code-suggestions-logs}

Si Code Suggestions est activé pour l'IDE, mais que les suggestions ne s'affichent toujours pas :

1. Dans votre IDE, ouvrez l'éditeur de paramètres :
   - Pour macOS, appuyez sur <kbd>Commande</kbd>+<kbd>,</kbd>.
   - Pour Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>,</kbd>.
1. Accédez aux paramètres **Autre** :
   - Dans VS Code, sélectionnez **Extensions** > **GitLab** > **Autre**.
   - Dans GitLab Web IDE, sélectionnez **Extensions** > **GitLab Workflow** > **Autre**.
1. Sous **GitLab : déboguer**, cochez la case.
   - Pour Web IDE, vous devez avoir les [extensions marketplace](../../web_ide/_index.md#manage-extensions) activées.
1. Dans le menu supérieur, sélectionnez **Afficher** > **Sortie** pour ouvrir le panneau inférieur, puis :
   - Dans la palette de commandes, sélectionnez `GitLab: Show Extension Logs`.
   - Dans le panneau inférieur, à droite, sélectionnez la liste déroulante pour filtrer les journaux. Sélectionnez **GitLab**.
1. Dans l'éditeur de paramètres, accédez aux paramètres **GitLab Duo**.
1. Décochez puis recochez la case **Suggestions de code GitLab Duo**.

### Désactiver la diffusion en continu des résultats de génération de code {#disable-streaming-of-code-generation-results}

Par défaut, la génération de code diffuse le code généré par l'IA en continu. La diffusion en continu envoie le code généré à votre éditeur de manière incrémentielle, plutôt que d'attendre que l'extrait de code complet soit généré. Cela permet une expérience plus interactive et réactive.

Si vous préférez voir les résultats de la génération de code uniquement lorsqu'ils sont complets, vous pouvez désactiver la diffusion en continu. La désactivation de la diffusion en continu signifie que les requêtes de génération de code peuvent être perçues comme prenant plus de temps à s'exécuter. Pour désactiver la diffusion en continu :

1. Dans VS Code, ouvrez l'éditeur de paramètres :
   - Pour macOS, appuyez sur <kbd>Commande</kbd>+<kbd>,</kbd>.
   - Pour Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>,</kbd>.
1. Dans le coin supérieur droit, sélectionnez **Ouvrir les paramètres (JSON)** pour modifier votre fichier `settings.json` :

   ![Les icônes dans le coin supérieur droit de VS Code, incluant « Ouvrir les paramètres ».](img/open_settings_v17_5.png)
1. Dans votre fichier `settings.json`, ajoutez cette ligne, ou définissez-la sur `false` si elle existe déjà :

   ```json
   "gitlab.featureFlags.streamCodeGenerations": false,
   ```

1. Enregistrez vos modifications.

### Erreur : la connexion directe échoue {#error-direct-connection-fails}

{{< history >}}

- Connexion directe [introduite](https://gitlab.com/groups/gitlab-org/-/epics/13252) dans GitLab 17.2.

{{< /history >}}

Pour réduire la latence, l'extension GitLab pour VS Code tente d'envoyer les requêtes de complétion de suggestions directement à GitLab Cloud Connector, en contournant l'instance GitLab. Cette connexion réseau n'utilise pas les paramètres de proxy et de certificat de l'extension VS Code.

Si votre instance GitLab ne prend pas en charge les connexions directes, ou si votre réseau empêche l'extension de se connecter à GitLab Cloud Connector, vous pouvez voir ces avertissements dans vos journaux :

```plaintext
Failed to fetch direct connection details from GitLab instance.
Code suggestion requests will be sent to GitLab instance.
```

Cette erreur signifie que votre instance ne prend pas en charge les connexions directes ou qu'elle est mal configurée.

Si vous voyez cette erreur, l'extension ne peut pas se connecter à GitLab Cloud Connector et revient à utiliser votre instance GitLab :

```plaintext
Direct connection for code suggestions failed.
Code suggestion requests will be sent to your GitLab instance.
```

La connexion indirecte via votre instance GitLab est environ 100 ms plus lente, mais fonctionne de la même manière. Ce problème est souvent causé par des problèmes de connexion réseau, comme ceux liés au pare-feu de votre réseau local ou aux paramètres de proxy.

## Dépannage des IDE JetBrains {#jetbrains-ides-troubleshooting}

La documentation suivante concerne le dépannage spécifique à Code Suggestions pour les IDE JetBrains.

Pour le dépannage non spécifique à Code Suggestions pour les IDE JetBrains, consultez [le dépannage JetBrains](../../../../editor_extensions/jetbrains_ide/jetbrains_troubleshooting.md).

### Suggestions non affichées dans les IDE JetBrains {#suggestions-not-displayed-in-jetbrains-ides}

1. Dans le menu **Outils** > **GitLab Duo**, sélectionnez **Vérifier la configuration**. Vérifiez que le bilan de santé est réussi.
1. Vérifiez que votre IDE JetBrains prend en charge nativement le langage du fichier sur lequel vous travaillez. Accédez à **Paramètres** > **Langages et frameworks** pour afficher la liste complète des langages et frameworks pris en charge par votre IDE JetBrains.

### Erreur : `unable to find valid certification path to requested target` {#error-unable-to-find-valid-certification-path-to-requested-target}

Le plugin GitLab Duo vérifie les informations du certificat TLS avant de se connecter à votre instance GitLab. Vous pouvez [ajouter un certificat SSL personnalisé](../../../../editor_extensions/jetbrains_ide/setup.md#add-a-custom-certificate-for-code-suggestions).

### Erreur : `Failed to check token` {#error-failed-to-check-token}

Cette erreur se produit lorsque l'URL de l'instance de connexion fournie et le jeton d'authentification transmis au processus du serveur de langage GitLab sont invalides. Pour réactiver Code Suggestions :

1. Dans votre IDE, dans la barre supérieure, sélectionnez le nom de votre IDE, puis sélectionnez **Paramètres**.
1. Dans la barre latérale gauche, sélectionnez **Outils** > **GitLab Duo**.
1. Sous **Connexion**, sélectionnez **Vérifier la configuration**.
1. Mettez à jour vos informations de **Connexion** si nécessaire.
1. Sélectionnez **Vérifier la configuration** et confirmez que l'authentification réussit.
1. Sélectionnez **OK** ou **Sauvegarder**.

## Dépannage de Microsoft Visual Studio {#microsoft-visual-studio-troubleshooting}

La documentation suivante concerne le dépannage spécifique à Code Suggestions pour Microsoft Visual Studio.

Pour le dépannage non spécifique à Code Suggestions pour Microsoft Visual Studio, consultez [le dépannage de Visual Studio](../../../../editor_extensions/visual_studio/visual_studio_troubleshooting.md).

### IntelliCode est manquant {#intellicode-is-missing}

Code Suggestions nécessite le composant IntelliCode de Visual Studio. Si le composant est manquant, vous pouvez voir une erreur comme celle-ci au démarrage de Visual Studio :

```plaintext
SetSite failed for package [VisualStudioPackage]Source: 'Microsoft.VisualStudio.Composition'
Description: Expected 1 export(s) with contract name "Microsoft.VisualStudio.Language.Suggestions.SuggestionServiceBase"
but found 0 after applying applicable constraints.

Microsoft.VisualStudio.Composition.CompositionFailedException:
Expected 1 export(s) with contract name "Microsoft.VisualStudio.Language.Suggestions.SuggestionServiceBase"
but found 0 after applying applicable constraints.

  at Microsoft.VisualStudio.Composition.ExportProvider.GetExports(ImportDefinition importDefinition)
  at Microsoft.VisualStudio.Composition.ExportProvider.GetExports[T,TMetadataView](String contractName, ImportCardinality cardinality)
  at Microsoft.VisualStudio.Composition.ExportProvider.GetExport[T,TMetadataView](String contractName)
  at Microsoft.VisualStudio.Composition.ExportProvider.GetExportedValue[T]()
  at Microsoft.VisualStudio.ComponentModelHost.ComponentModel.GetService[T]()
[...]
```

Pour résoudre ce problème, installez le composant IntelliCode :

1. Dans le menu Démarrer de Windows, recherchez **Visual Studio Installer** et ouvrez-le.
1. Sélectionnez votre instance Visual Studio, puis sélectionnez **Modifier**.
1. Dans l'onglet **Composants individuels**, recherchez **IntelliCode**.
1. Cochez la case du composant, puis en bas à droite, sélectionnez **Modifier**.
1. Attendez que Visual Studio Installer termine l'installation.

### Suggestions non affichées dans Microsoft Visual Studio {#suggestions-not-displayed-in-microsoft-visual-studio}

1. Assurez-vous d'avoir correctement [configuré l'extension](../../../../editor_extensions/visual_studio/setup.md).
1. Dans le menu **Outils** > **Options**, trouvez l'option **GitLab**. Vérifiez que **Log Level** est défini sur **Déboguer**.
1. Dans **Afficher** > **Sortie**, ouvrez le journal de l'extension. Changez la liste déroulante sur **GitLab Extension** comme filtre de journal.
1. Vérifiez que le journal de débogage contient une sortie similaire :

```shell
14:48:21:344 GitlabProposalSource.GetCodeSuggestionAsync
14:48:21:344 LsClient.SendTextDocumentCompletionAsync("GitLab.Extension.Test\TestData.cs", 34, 0)
14:48:21:346 LS(55096): time="2023-07-17T14:48:21-05:00" level=info msg="update context"
```

Si une autre extension fournit des fonctionnalités similaires de suggestion ou de complétion, l'extension peut ne pas renvoyer de suggestions. Pour résoudre ce problème :

1. Désactivez toutes les autres extensions Visual Studio.
1. Confirmez que vous recevez maintenant des suggestions Code Suggestions.
1. Réactivez les extensions une par une, en testant Code Suggestions à chaque fois, pour trouver celle qui crée un conflit.

## Dépannage de Neovim {#neovim-troubleshooting}

La documentation suivante concerne le dépannage spécifique à Code Suggestions pour Neovim.

Pour le dépannage non spécifique à Code Suggestions pour Neovim, consultez [le dépannage Neovim](../../../../editor_extensions/neovim/neovim_troubleshooting.md).

### Échec des complétions de code {#code-completions-fails}

1. Confirmez que `omnifunc` est défini dans Neovim :

   ```lua
   :verbose set omnifunc?
   ```

1. Confirmez que le serveur de langage est actif en exécutant cette commande dans Neovim :

   ```lua
   :lua =vim.lsp.get_active_clients()
   ```

1. Consultez les journaux du serveur de langage dans `~/.local/state/nvim/lsp.log`.
1. Inspectez le chemin de journal `vim.lsp` pour détecter des erreurs en exécutant cette commande dans Neovim :

   ```lua
   :lua =vim.cmd('view ' .. vim.lsp.get_log_path())
   ```

## Problèmes de latence avec la complétion de code {#latency-issues-with-code-completion}

Si vous êtes assigné à un siège dans un projet pour lequel un modèle spécifique est sélectionné pour la complétion de code :

- Votre extension IDE désactive la [connexion directe à la passerelle d'IA](_index.md#direct-and-indirect-connections)
- Les requêtes de complétion de code transitent par le monolithe GitLab, qui sélectionne ensuite le modèle spécifié pour répondre à ces requêtes.

Cela peut entraîner une latence accrue pour les requêtes de complétion de code.
