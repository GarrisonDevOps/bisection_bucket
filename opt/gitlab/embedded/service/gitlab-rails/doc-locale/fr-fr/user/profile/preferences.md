---
stage: Facilitated functionality
group: Facilitated functionality
info: For more information, see <https://handbook.gitlab.com/handbook/product/categories/#facilitated-functionality>
title: Préférences du profil
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez mettre à jour vos préférences pour modifier l'apparence de GitLab.

## Changer le mode {#change-the-mode}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/28252) dans GitLab 13.1.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/524846) de version expérimentale à version bêta dans GitLab 17.11.
- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/470413) de **Apparence** à **Mode** dans GitLab 18.1.

{{< /history >}}

Vous pouvez modifier le mode de couleur de l'interface pour qu'il soit clair, sombre, ou se mette à jour automatiquement en fonction des préférences de l'appareil.

Pour modifier l'apparence :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Dans la section **Mode**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

## Changer le thème de navigation {#change-the-navigation-theme}

{{< history >}}

- [Modifié](https://gitlab.com/gitlab-org/gitlab/-/issues/470413) de **Thème de couleur** à **Thème de navigation** dans GitLab 18.1.
- Thèmes : Light Indigo, Light Blue, Light Green et Light Red [supprimés](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200475) dans GitLab 18.4.

{{< /history >}}

Vous pouvez modifier le thème de navigation de l'interface GitLab. Ces couleurs sont affichées dans la barre latérale gauche. L'utilisation de thèmes de navigation individuels peut vous aider à différencier vos différentes instances GitLab.

Pour modifier le thème de navigation :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Dans la section **Thème**, sélectionnez un thème.

## Changer le thème de coloration syntaxique {#change-the-syntax-highlighting-theme}

La coloration syntaxique est une fonctionnalité des éditeurs de code et des IDE. Le système de coloration attribue une couleur à chaque type de code, comme les chaînes de caractères et les commentaires.

Pour modifier le thème de coloration syntaxique :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Dans la section **Coloration syntaxique**, sélectionnez un thème.
1. Sélectionnez **Enregistrer les modifications**.

Pour afficher le thème de coloration syntaxique mis à jour, actualisez la page de votre projet.

Pour personnaliser le thème de coloration syntaxique, vous pouvez également [utiliser l'API des paramètres d'application](../../api/settings.md#available-settings). Utilisez `default_syntax_highlighting_theme` et `default_dark_syntax_highlighting_theme` pour modifier les couleurs de coloration syntaxique à un niveau plus granulaire.

Si ces étapes ne fonctionnent pas, votre langage de programmation n'est peut-être pas pris en charge par les outils de coloration syntaxique. Pour plus d'informations, consultez [Rouge Ruby Library](https://github.com/rouge-ruby/rouge) pour obtenir des conseils sur les fichiers de code et les snippets. Consultez [Monaco Editor](https://microsoft.github.io/monaco-editor/) et [Monarch](https://microsoft.github.io/monaco-editor/monarch.html) pour obtenir des conseils sur le Web IDE.

## Changer les couleurs des diffs {#change-the-diff-colors}

Les diffs utilisent deux couleurs d'arrière-plan différentes pour montrer les modifications entre les versions du code. Par défaut, le fichier d'origine est en rouge et les modifications sont en vert.

Pour modifier les couleurs des diffs :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Accédez à la section **Diffs**.
1. Sélectionnez une couleur ou saisissez un code couleur.
1. Sélectionnez **Enregistrer les modifications**.

Pour revenir aux couleurs par défaut, effacez les zones de texte **Couleur des lignes supprimées** et **Couleur des lignes ajoutées**, puis sélectionnez **Enregistrer les modifications**.

## Comportement {#behavior}

Utilisez la section **Comportement** pour personnaliser le comportement de la mise en page du système et des vues par défaut. Vous pouvez modifier la largeur de la mise en page et choisir le contenu par défaut pour votre page d'accueil, et les pages de vue d'ensemble des groupes et des projets. Vous disposez d'options pour personnaliser l'apparence et le fonctionnement, comme le rendu des espaces, l'affichage des fichiers et l'automatisation du texte.

Vous pouvez également utiliser cette section pour définir un espace de nommage par défaut pour GitLab Duo.

### Modifier la largeur de la mise en page dans l'interface {#change-the-layout-width-on-the-ui}

Vous pouvez étirer le contenu de l'interface GitLab pour remplir toute la page. Par défaut, le contenu de la page est fixé à 1 280 pixels de large.

Pour modifier la largeur de la mise en page de votre interface :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Sous **Largeur de la mise en page**, choisissez **Corrigées** ou **Fluide**.
1. Sélectionnez **Enregistrer les modifications**.

### Définir l'éditeur de texte par défaut {#set-the-default-text-editor}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/423104) dans GitLab 17.7.
- La valeur par défaut pour les nouveaux utilisateurs [a été définie sur l'éditeur de texte enrichi](https://gitlab.com/gitlab-org/gitlab/-/issues/536611) dans la version 18.2.

{{< /history >}}

Par défaut, tous les nouveaux utilisateurs voient l'**Éditeur de texte enrichi** lors de la modification du contenu. Vous pouvez modifier l'éditeur par défaut pour la modification du contenu dans GitLab.

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Sous **Éditeur de texte par défaut**, vérifiez que la case **Activer l'éditeur de texte par défaut** est cochée.
1. Choisissez **Éditeur de texte enrichi** ou **Éditeur de texte brut** comme éditeur par défaut.
1. Sélectionnez **Enregistrer les modifications**.

### Choisir votre page d'accueil {#choose-your-homepage}

{{< history >}}

- [Les options de page d'accueil ont été modifiées](https://gitlab.com/groups/gitlab-org/-/work_items/13066) dans GitLab 17.9 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `your_work_projects_vue`. Fonctionnalité désactivée par défaut.
- [Les modifications des options de page d'accueil sont généralement disponibles](https://gitlab.com/gitlab-org/gitlab/-/issues/465889) dans GitLab 17.10. Le feature flag `your_work_projects_vue` a été supprimé.
- [Page d'accueil personnelle introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/546151) dans GitLab 18.1 [avec un feature flag](../../administration/feature_flags/_index.md) nommé `personal_homepage`. Fonctionnalité désactivée par défaut.
- [Page d'accueil personnelle activée sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/554048) dans GitLab 18.4 pour un sous-ensemble d'utilisateurs.
- [Page d'accueil personnelle activée sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/groups/gitlab-org/-/work_items/17932) dans GitLab 18.5.
- [Page d'accueil personnelle généralement disponible](https://gitlab.com/gitlab-org/gitlab/-/issues/561388) dans GitLab 19.4. Le feature flag `personal_homepage` a été supprimé.

{{< /history >}}

Contrôlez la page que vous affichez lorsque vous sélectionnez le logo GitLab ({{< icon name="tanuki" >}}). Vous pouvez définir votre page d'accueil sur Page d'accueil personnelle (par défaut), Vos projets auxquels vous avez contribué, Vos groupes, Votre activité et d'autres contenus.

Pour choisir la vue de votre page d'accueil :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Dans la liste déroulante **Page d'accueil**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

### Personnaliser le contenu par défaut de la page de vue d'ensemble de votre groupe {#customize-default-content-on-your-group-overview-page}

Vous pouvez modifier le contenu principal de la page de vue d'ensemble de votre groupe. La page de vue d'ensemble de votre groupe est la page qui s'affiche lorsque vous sélectionnez **Groupes** dans la barre latérale gauche. Vous pouvez personnaliser le contenu par défaut de la page de vue d'ensemble de votre groupe en choisissant parmi les options suivantes :

- Tableau de bord des détails (par défaut), qui inclut une vue d'ensemble des activités et des projets du groupe.
- Tableau de bord de sécurité, qui peut inclure les politiques de sécurité du groupe et d'autres sujets liés à la sécurité.

Pour plus d'informations, consultez [Groupes](../group/_index.md).

Pour modifier le contenu par défaut de la page de vue d'ensemble de votre groupe :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Dans la liste déroulante **Contenu de la vue d'ensemble du groupe**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

### Personnaliser le contenu par défaut de la page de vue d'ensemble de votre projet {#customize-default-content-on-your-project-overview-page}

La page de vue d'ensemble de votre projet est la page que vous affichez lorsque vous sélectionnez **Vue d'ensemble du projet** dans la barre latérale gauche. Vous pouvez définir la page principale de vue d'ensemble de votre projet sur la page Activité, le fichier README et d'autres contenus.

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Dans la liste déroulante **Contenu de la vue d'ensemble du projet**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

### Définir un espace de nommage GitLab Duo par défaut {#set-a-default-gitlab-duo-namespace}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/issues/552081) dans GitLab 18.3 avec un [flag](../../administration/feature_flags/_index.md) nommé `ai_user_default_duo_namespace`. Fonctionnalité désactivée par défaut.
- [Activation](https://gitlab.com/gitlab-org/gitlab/-/issues/560319) dans GitLab 18.4.
- [Suppression](https://gitlab.com/gitlab-org/gitlab/-/issues/569140) du feature flag `ai_user_default_duo_namespace` dans GitLab 18.7.

{{< /history >}}

Définissez un espace de nommage GitLab Duo par défaut pour vous assurer que GitLab Duo est disponible pour une utilisation avec votre projet. Votre espace de nommage GitLab Duo par défaut détermine vos [modèles d'IA](../gitlab_duo/model_selection.md) disponibles et les fonctionnalités GitLab Duo, ainsi que votre consommation de [GitLab Credits](../../subscriptions/gitlab_credits.md).

Votre espace de nommage GitLab Duo par défaut détermine la disponibilité des fonctionnalités et la consommation de crédits dans les scénarios suivants :

- Vous n'êtes pas membre du projet sur lequel vous travaillez.
- Vous appartenez à plusieurs espaces de nommage GitLab Duo.
- Vous travaillez dans votre IDE avec un projet qui ne dispose pas d'un remote GitLab configuré.
- Vous utilisez GitLab Duo dans l'interface de ligne de commande.

Lorsque vous travaillez dans un projet ou un groupe dont vous êtes membre direct ou hérité, le groupe principal de ce projet ou groupe est utilisé à la place pour la disponibilité des fonctionnalités et la consommation de crédits :

- Si vous utilisez les fonctionnalités GitLab Duo dans un projet dont vous êtes membre, l'utilisation est facturée au groupe principal de ce projet.
- Si vous utilisez les fonctionnalités GitLab Duo en dehors d'un projet (par exemple, dans votre IDE sans projet ouvert ou dans l'interface de ligne de commande), l'utilisation est facturée à votre espace de nommage par défaut.
- Si vous utilisez les fonctionnalités GitLab Duo dans un projet dont vous n'êtes pas membre, l'utilisation est facturée à votre espace de nommage par défaut.

Si vous ne définissez pas d'espace de nommage par défaut, GitLab Duo Agentic Chat et la plateforme d'agents GitLab Duo sont désactivés.

Pour définir un espace de nommage GitLab Duo par défaut :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Dans la liste déroulante **Groupe GitLab Duo par défaut**, sélectionnez le groupe que vous souhaitez définir comme valeur par défaut.
1. Sélectionnez **Enregistrer les modifications**.

#### Résolution de l'espace de nommage dans votre environnement local {#namespace-resolution-in-your-local-environment}

{{< history >}}

- L'accès aux espaces de nommage par défaut des utilisateurs pour les IDE a été [introduit](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2043) dans GitLab 18.10.
- L'accès aux espaces de nommage par défaut des utilisateurs a été introduit dans GitLab for VS Code 6.71.7.
- L'accès aux espaces de nommage par défaut des utilisateurs a été introduit dans GitLab Duo CLI 8.76.0.
- Le paramètre d'espace de nommage par défaut dans les extensions d'éditeur a été [supprimé](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2369) dans GitLab 19.4.
  - [Supprimé](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.46.0) dans le plugin GitLab Duo pour les IDE JetBrains 3.46.0.
  - [Supprimé](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.90.0) dans GitLab for VS Code 6.90.0.

{{< /history >}}

Lorsque vous utilisez GitLab Duo dans un IDE ou l'interface de ligne de commande, le premier espace de nommage disponible détermine la disponibilité des fonctionnalités et la consommation de crédits. En plus des autres exigences de la plateforme d'agents, le projet sur lequel vous travaillez doit se trouver dans un [espace de nommage de groupe](../namespace/_index.md).

GitLab Duo recherche un espace de nommage dans l'ordre suivant :

1. L'espace de nommage du projet, si votre projet est lié à un dépôt distant dans GitLab.
1. L'espace de nommage par défaut défini dans vos préférences utilisateur.

Si le premier espace de nommage identifié n'a pas accès à la fonctionnalité demandée ou aux crédits disponibles, la fonctionnalité n'est pas disponible. GitLab Duo ne bascule pas vers l'espace de nommage suivant dans la liste.

Si votre projet n'est pas lié à un dépôt distant dans GitLab, vous devez [définir un espace de nommage GitLab Duo par défaut](#set-a-default-gitlab-duo-namespace) dans vos préférences utilisateur.

### Masquer les boutons de raccourci {#hide-shortcut-buttons}

Les boutons de raccourci précèdent la liste des fichiers sur la page de vue d'ensemble d'un projet. Ces boutons fournissent des liens vers des parties d'un projet, comme le fichier README ou les contrats de licence.

Pour masquer les boutons de raccourci sur la page de vue d'ensemble du projet :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Décochez la case **Afficher les boutons de raccourci au-dessus des fichiers dans la vue d'ensemble du projet**.
1. Sélectionnez **Enregistrer les modifications**.

### Afficher les espaces blancs dans le Web IDE {#show-whitespace-characters-in-the-web-ide}

Les espaces blancs sont tous les caractères vides dans un texte, comme les espaces et les indentations. Vous pouvez utiliser les espaces blancs pour structurer le contenu dans le code. Si votre langage de programmation est sensible aux espaces blancs, le Web IDE peut détecter les modifications qui leur sont apportées.

Pour afficher les espaces blancs dans le Web IDE :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Cochez la case **Afficher les espaces blancs dans le Web IDE**.
1. Sélectionnez **Enregistrer les modifications**.

Vous pouvez voir les modifications apportées aux espaces blancs dans les diffs.

Pour afficher les diffs dans le Web IDE, suivez les étapes ci-dessous :

1. Dans la barre latérale gauche, sélectionnez **Contrôle de source** ({{< icon name="branch" >}}).
1. Sous l'onglet **Modifications**, sélectionnez votre fichier.

### Afficher les modifications apportées aux espaces dans les diffs {#show-whitespace-changes-in-diffs}

Affichez les modifications apportées aux espaces blancs dans les fichiers de diff. Pour plus d'informations sur les espaces blancs, consultez la tâche précédente.

Pour afficher les modifications apportées aux espaces blancs dans les diffs :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Cochez la case **Afficher les modifications apportées aux espaces dans les diffs**.
1. Sélectionnez **Enregistrer les modifications**.

Pour plus d'informations sur les diffs, consultez [Changer les couleurs des diffs](#change-the-diff-colors).

### Afficher un fichier par page dans une merge request {#show-one-file-per-page-in-a-merge-request}

L'onglet **Modifications** vous permet d'afficher toutes les modifications de fichiers d'une merge request sur une seule page. Vous pouvez également choisir d'afficher un fichier à la fois.

Pour afficher un fichier par page dans l'onglet **Modifications** :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Cochez la case **Afficher un fichier à la fois sur l'onglet Modifications de la requête de fusion**.
1. Sélectionnez **Enregistrer les modifications**.

Ensuite, pour naviguer entre les fichiers dans l'onglet **Modifications**, sous chaque fichier, sélectionnez les boutons **Précédent** et **Suivant**.

### Encadrement automatique des caractères {#auto-enclose-characters}

Ajoutez automatiquement le caractère de fermeture correspondant au texte lorsque vous saisissez le caractère d'ouverture. Par exemple, vous pouvez insérer automatiquement un crochet fermant lorsque vous saisissez un crochet ouvrant. Ce paramètre fonctionne uniquement dans les zones de description et de commentaire et pour les caractères suivants : `**"`, `'`, ```, `(`, `[`, `{`, `<`, `*`, `_**`.

Pour encadrer automatiquement les caractères dans les zones de description et de commentaire :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Cochez la case **Encadrer la sélection de texte lors de la saisie de guillemets ou de crochets**.
1. Sélectionnez **Enregistrer les modifications**.

Dans une zone de description ou de commentaire, vous pouvez maintenant saisir un mot, le mettre en surbrillance, puis saisir un caractère d'ouverture. Au lieu de remplacer le texte, le caractère de fermeture est ajouté à la fin.

### Automatiser les nouveaux éléments de liste {#automate-new-list-items}

Créez un nouvel élément de liste lorsque vous appuyez sur <kbd>Entrée</kbd> dans une liste dans les zones de description et de commentaire.

Pour ajouter un nouvel élément de liste lorsque vous appuyez sur la touche <kbd>Entrée</kbd> :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Cochez la case **Ajouter automatiquement de nouveaux éléments à une liste**.
1. Sélectionnez **Enregistrer les modifications**.

### Désactiver l'autocomplétion des émojis {#turn-off-emoji-autocomplete}

Par défaut, lorsque vous saisissez un deux-points (`:`) dans une zone de description ou de commentaire, GitLab suggère des émojis correspondants. Si vous utilisez les deux-points pour d'autres raisons, par exemple dans des langues qui mettent un espace avant les deux-points, vous pouvez désactiver ces suggestions. Lorsque cette option est désactivée, vous pouvez toujours insérer des émojis par d'autres moyens, comme le copier-coller.

Pour désactiver l'autocomplétion des émojis :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Décochez la case **Activer l'autocomplétion des émojis**.
1. Sélectionnez **Enregistrer les modifications**.

### Maintenir l'indentation du curseur {#maintain-cursor-indentation}

Maintenez l'indentation lorsque vous appuyez sur <kbd>Entrée</kbd>. Le curseur sur la nouvelle ligne est automatiquement indenté de la même manière que la ligne précédente. Ce paramètre fonctionne uniquement dans les zones de description et de commentaire.

Pour ajouter un nouvel élément de liste lorsque vous appuyez sur la touche <kbd>Entrée</kbd> :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Cochez la case **Maintenir l'indentation du curseur**.
1. Sélectionnez **Enregistrer les modifications**.

### Modifier la largeur de tabulation {#change-the-tab-width}

Modifiez la taille par défaut des tabulations dans les diffs, les blobs et les snippets. Le Web IDE, l'éditeur de fichiers et l'éditeur Markdown ne prennent pas en charge cette fonctionnalité.

Pour ajuster la largeur de tabulation par défaut :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Faites défiler jusqu'à la section **Comportement**.
1. Pour **Largeur de tabulation**, saisissez une valeur.
1. Sélectionnez **Enregistrer les modifications**.

## Localisation {#localization}

Modifiez les paramètres de localisation tels que votre langue, le jour de début du calendrier et les préférences d'heure.

### Modifier la langue d'affichage dans l'interface GitLab {#change-your-display-language-on-the-gitlab-ui}

GitLab prend en charge plusieurs langues dans l'interface.

Pour choisir une langue pour l'interface GitLab :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Accédez à la section **Localisation**.
1. Sous **Langage**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

Vous devrez peut-être actualiser votre page pour afficher la langue mise à jour.

### Personnaliser le jour de début de votre calendrier de contributions {#customize-your-contribution-calendar-start-day}

Choisissez le jour de la semaine par lequel le calendrier de contributions commence. Le calendrier de contributions affiche les contributions au projet au cours de l'année passée. Vous pouvez consulter ce calendrier sur chaque profil utilisateur. Pour accéder à votre profil utilisateur :

- Dans le coin supérieur droit, sélectionnez votre avatar, puis sélectionnez votre nom ou votre nom d'utilisateur.

Pour modifier le jour de début de votre calendrier de contributions :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Accédez à la section **Localisation**.
1. Sous **Premier jour de la semaine**, sélectionnez une option.
1. Sélectionnez **Enregistrer les modifications**.

Après avoir modifié le jour de début de votre calendrier, actualisez la page de votre profil utilisateur.

### Afficher les heures exactes au lieu des heures relatives {#show-exact-times-instead-of-relative-times}

Personnalisez le format utilisé pour afficher les heures des activités sur vos pages de vue d'ensemble des groupes et des projets, ainsi que sur les profils utilisateur. Vous pouvez afficher les heures dans un format :

- Format relatif, par exemple `30 minutes ago`.
- Format absolu, par exemple `September 3, 2022, 3:57 PM`.

Pour utiliser les heures exactes dans l'interface GitLab :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Accédez à la section **Date et heure**.
1. Décochez la case **Dates et heures relatives à l'heure actuelle**.
1. Sélectionnez **Enregistrer les modifications**.

### Personnaliser le format de l'heure {#customize-time-format}

Vous pouvez personnaliser le format utilisé pour afficher les heures des activités sur vos pages de vue d'ensemble des groupes et des projets, ainsi que sur les profils utilisateur. Vous pouvez afficher les heures selon les formats suivants :

- Format 12 heures. Par exemple : `2:34 PM`.
- Format 24 heures. Par exemple : `14:34`.

Vous pouvez également suivre le paramètre de votre système.

Pour personnaliser le format de l'heure :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Accédez à la section **Date et heure**.
1. Sous **Format de l'heure**, sélectionnez l'option **Système**, **12 heures** ou **24 heures**.
1. Sélectionnez **Enregistrer les modifications**.

## Identités utilisateur dans les jetons web JSON des jobs CI {#user-identities-in-ci-job-json-web-tokens}

Les jobs CI/CD génèrent des jetons web JSON, qui peuvent inclure une liste de vos identités externes. Au lieu d'effectuer des appels API séparés pour obtenir des comptes individuels, vous pouvez retrouver vos identités utilisateur dans un seul jeton d'authentification.

Les identités externes ne sont pas incluses par défaut. Pour activer l'inclusion des identités externes, consultez [Payload du jeton](../../ci/secrets/id_token_authentication.md#token-payload).

## Contrôler l'engagement des abonnés {#control-follower-engagement}

Désactivez la possibilité de suivre ou d'être suivi par d'autres utilisateurs GitLab. Par défaut, votre profil utilisateur, y compris votre nom et votre photo de profil, est public dans les onglets **Abonnements** des autres utilisateurs. Lorsque vous désactivez ce paramètre :

- GitLab supprime tous vos abonnés et abonnements.
- GitLab supprime automatiquement votre profil utilisateur des pages de chaque connexion.

Pour supprimer la possibilité d'être suivi par d'autres utilisateurs et de les suivre :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Décochez la case **Activer le suivi des utilisateurs**.
1. Sélectionnez **Enregistrer les modifications**.

Pour accéder à vos onglets **Abonnés** et **Abonnements** :

- Dans le coin supérieur droit, sélectionnez votre avatar.
- Sélectionnez **Abonnés** ou **Abonnements**.

## Intégrer votre instance GitLab à des services tiers {#integrate-your-gitlab-instance-with-third-party-services}

Accordez à des services tiers l'accès pour améliorer l'expérience GitLab.

### Intégrer votre instance GitLab à Ona {#integrate-your-gitlab-instance-with-ona}

Configurez votre instance GitLab avec Ona lorsque vous souhaitez lancer et gérer du code directement depuis votre navigateur GitLab. Ona prépare et crée automatiquement des environnements de développement pour vos projets.

Pour intégrer Ona :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Trouvez la section **Intégrations**.
1. Cochez la case **Activer l'intégration d'Ona**.
1. Sélectionnez **Enregistrer les modifications**.

### Intégrer votre instance GitLab à Sourcegraph {#integrate-your-gitlab-instance-with-sourcegraph}

GitLab prend en charge l'intégration Sourcegraph pour tous les projets publics sur GitLab.

Pour intégrer Sourcegraph :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Trouvez la section **Intégrations**.
1. Cochez la case **Activer l'intelligence de code intégrée sur les vues de code**.
1. Sélectionnez **Enregistrer les modifications**.

Vous devez être l'administrateur de l'instance GitLab pour configurer GitLab avec Sourcegraph.

### Intégrer la marketplace d'extensions {#integrate-with-the-extension-marketplace}

{{< details >}}

- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [Introduit](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/151352) en tant que [version bêta](../../policy/development_stages_support.md#beta) dans GitLab 17.0 [avec des feature flags](../../administration/feature_flags/_index.md) nommés `web_ide_oauth` et `web_ide_extensions_marketplace`. Fonctionnalité désactivée par défaut.
- `web_ide_oauth` [activé sur GitLab.com, GitLab Self-Managed et GitLab Dedicated](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163181) dans GitLab 17.4.
- `web_ide_extensions_marketplace` [activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/issues/459028) dans GitLab 17.4.
- `web_ide_oauth` [supprimé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/167464) dans GitLab 17.5.
- Activé par défaut pour les [workspaces](../workspace/_index.md) dans GitLab 17.6. Les workspaces ne nécessitent aucun feature flag pour que la marketplace d'extensions soit disponible.
- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/508996) du feature flag `vscode_extension_marketplace_settings` [feature flag](../../administration/feature_flags/_index.md) dans GitLab 17.10. Fonctionnalité désactivée par défaut.
- `web_ide_extensions_marketplace` [activé sur GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662), et `vscode_extension_marketplace_settings` [activé sur GitLab.com et GitLab Self-Managed](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662) dans GitLab 17.11.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192659) dans GitLab 18.1. Les feature flags `web_ide_extensions_marketplace` et `vscode_extension_marketplace_settings` ont été supprimés.

{{< /history >}}

La marketplace d'extensions VS Code donne accès à des extensions qui améliorent les fonctionnalités du Web IDE et des workspaces.

Prérequis :

- Pour GitLab Self-Managed et GitLab Dedicated, un administrateur GitLab doit [activer le registre des extensions](../../administration/settings/vscode_extension_marketplace.md#enable-the-extension-registry).
- Pour les utilisateurs d'entreprise, un propriétaire de groupe doit [activer la marketplace d'extensions](../enterprise_user/_index.md#enable-the-extension-marketplace-for-enterprise-users) pour le groupe associé.

Pour intégrer la marketplace d'extensions :

1. Dans le coin supérieur droit, sélectionnez votre avatar.
1. Sélectionnez **Préférences**.
1. Accédez à la section **Intégrations**.
1. Cochez la case **Activer la marketplace d'extensions**.
1. Dans l'accusé de réception de l'extension tierce, sélectionnez **Je comprends**.
1. Sélectionnez **Enregistrer les modifications**.
