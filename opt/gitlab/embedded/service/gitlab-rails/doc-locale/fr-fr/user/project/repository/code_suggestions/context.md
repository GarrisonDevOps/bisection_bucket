---
stage: AI Coding
group: DAP Repository Flows
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Sensibilité contextuelle des suggestions de code
---

Différentes informations sont disponibles pour aider GitLab Duo à prendre des décisions et à formuler des suggestions.

Les informations peuvent être disponibles :

- Toujours.
- En fonction de votre emplacement (le contexte change lorsque vous naviguez).

Le contexte suivant est disponible pour les suggestions de code.

## Toujours disponible {#always-available}

- Connaissances générales en programmation, bonnes pratiques et spécificités des langages.
- Le nom, l'extension et le contenu du fichier que vous consultez ou modifiez, y compris le contenu avant et après votre curseur.

## En fonction de l'emplacement {#based-on-location}

- Fichiers ouverts dans des onglets de l'IDE. Facultatif, mais activé par défaut.
  - Prérequis :
    - GitLab 17.2 ou version ultérieure pour une pondération contextuelle optimale.
    - Extensions d'IDE prises en charge. Pour les exigences de version, consultez [utiliser les fichiers ouverts comme contexte](#using-open-files-as-context).
  - Ces fichiers fournissent à GitLab Duo des informations sur les normes et pratiques de votre projet.
  - Fermez les fichiers si vous ne souhaitez pas qu'ils soient utilisés comme contexte.
  - Les fichiers ouverts ou modifiés le plus récemment sont prioritaires pour le contexte.
  - La complétion de code prend en charge tous les langages supportés par les suggestions de code.
  - La génération de code prend en charge uniquement les fichiers dans ces langages : Go, Java, JavaScript, Kotlin, Python, Ruby, Rust, TypeScript (fichiers `.ts` et `.tsx`), Vue et YAML.
- Fichiers importés dans le fichier que vous consultez ou modifiez. Facultatif, et désactivé par défaut.
  - Ces fichiers fournissent à GitLab Duo des informations sur les classes et méthodes de votre fichier.
  - Pris en charge pour les fichiers JavaScript et TypeScript, y compris les types de fichiers `.js`, `.jsx`, `.ts`, `.tsx` et `.vue`.
- Code sélectionné dans votre éditeur.
- Fichiers X-Ray du dépôt générés par les suggestions de code.

> [!note]
> Les secrets et les valeurs sensibles correspondant à des formats connus sont supprimés avant d'être utilisés pour générer du code. Cela s'applique aux fichiers ajoutés à l'aide de `/include`.

Pour plus d'informations sur la façon dont les suggestions de code utilisent le contexte dans les IDE, consultez la [documentation du serveur de langages GitLab](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp#use-open-tabs-as-context).

### Modifier ce que les suggestions de code utilisent comme contexte {#change-what-code-suggestions-uses-for-context}

Vous pouvez modifier si les suggestions de code utilisent ou non d'autres fichiers comme contexte.

#### Utiliser les fichiers ouverts comme contexte {#using-open-files-as-context}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/464767) dans GitLab 17.1 [avec le feature flag](../../../../administration/feature_flags/_index.md) `advanced_context_resolver`. Fonctionnalité désactivée par défaut.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/462750) dans GitLab 17.1 [avec le feature flag](../../../../administration/feature_flags/_index.md) `code_suggestions_context`. Fonctionnalité désactivée par défaut.
- [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/issues/276) dans GitLab pour VS Code 4.20.0.
- [Introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/issues/462) dans GitLab Duo pour JetBrains 2.7.0.
- [Ajouté](https://gitlab.com/gitlab-org/editor-extensions/gitlab.vim/-/merge_requests/152) au plugin GitLab Neovim le 16 juillet 2024.
- Les feature flags `advanced_context_resolver` et `code_suggestions_context` ont été activés sur GitLab.com dans GitLab 17.2 et sur GitLab Self-Managed dans GitLab 17.4.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/462750) dans GitLab 18.6. Le feature flag `code_suggestions_context` a été supprimé.

{{< /history >}}

Par défaut, les suggestions de code utilisent les fichiers ouverts dans votre IDE comme contexte lors de la formulation de suggestions. Cependant, vous pouvez désactiver ce paramètre.

Prérequis :

- GitLab 17.2 ou version ultérieure. Les versions antérieures de GitLab qui prennent en charge les suggestions de code ne peuvent pas pondérer le contenu des onglets ouverts plus fortement que les autres fichiers de votre projet.
- Une extension prise en charge :
  - Extension GitLab pour VS Code 6.2.2 ou version ultérieure.
  - Plugin GitLab Duo pour les IDE JetBrains 3.6.5 ou version ultérieure.
  - Plugin GitLab pour Neovim 1.1.0 ou version ultérieure.
  - Extension GitLab pour Visual Studio 0.51.0 ou version ultérieure.

Pour modifier les fichiers ouverts utilisés comme contexte :

{{< tabs >}}

{{< tab title="Visual Studio Code" >}}

1. Dans VS Code, ouvrez l'éditeur de paramètres :
   - Pour macOS, appuyez sur <kbd>Commande</kbd>+<kbd>,</kbd>.
   - Pour Windows ou Linux, appuyez sur <kbd>Ctrl</kbd>+<kbd>,</kbd>.
1. Sélectionnez **Extensions** > **GitLab** > **GitLab Duo**.
1. Sous **GitLab › Duo Code Suggestions : Open Tabs Context**, cochez ou décochez **Use the contents of open tabs as context**.

{{< /tab >}}

{{< tab title="JetBrains IDEs" >}}

1. Accédez à la barre de menu supérieure de votre IDE et sélectionnez **Paramètres**.
1. Dans la barre latérale gauche, développez **Outils**, puis sélectionnez **GitLab Duo**.
1. Sous **Additional languages**, cochez ou décochez **Send open tabs as context**.
1. Sélectionnez **Appliquer** ou **Sauvegarder**.

{{< /tab >}}

{{< /tabs >}}

#### Utiliser les fichiers importés comme contexte {#using-imported-files-as-context}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/514124) dans GitLab 17.9 [avec le feature flag](../../../../administration/feature_flags/_index.md) `code_suggestions_include_context_imports`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/issues/514124) dans GitLab 17.11.
- Feature flag `code_suggestions_include_context_imports` [supprimé](https://gitlab.com/gitlab-org/gitlab/-/issues/536129) dans GitLab 18.0.

{{< /history >}}

Utilisez les fichiers importés dans votre IDE pour fournir du contexte sur votre projet de code. Le contexte des fichiers importés est pris en charge pour les fichiers JavaScript et TypeScript, y compris les types de fichiers `.js`, `.jsx`, `.ts`, `.tsx` et `.vue`.
