---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Utilisez les revues de code des merge requests pour discuter et améliorer le code avant qu'il ne soit fusionné dans votre projet."
title: 'Tutoriel : passer en revue une merge request'
---

Les revues de code des merge requests contribuent à garantir que seul du code de haute qualité intègre votre base de code. Ce tutoriel vous montre comment effectuer la revue de code d'une merge request dans GitLab. Il vous guide à travers la structure de la merge request elle-même, puis le processus permettant de fournir des retours constructifs et utiles. À la fin du tutoriel, vous serez prêt à approuver la merge request ou à demander des modifications supplémentaires.

<i class="fa-youtube-play" aria-hidden="true"></i> Pour une vue d'ensemble, consultez [la revue de code des merge requests](https://www.youtube.com/watch?v=2MayfXKpU08&list=PLFGfElNsQthYDx0A_FaNNfUm9NHsK6zED&index=183).
<!-- Video published on 2023-04-29 -->

Pour effectuer la revue de code d'une merge request :

1. [Accéder à la merge request](#go-to-the-merge-request)
1. [Comprendre la structure des merge requests](#understand-the-structure-of-merge-requests)
1. [Obtenir une vue d'ensemble](#get-a-high-level-view-of-the-merge-request)
   1. [Vérifier les tickets liés](#check-related-issues)
   1. [Vérifier la barre latérale](#check-the-sidebar)
   1. [Vérifier les commentaires](#check-the-comments)
1. [Lire les modifications du code](#read-the-code-changes)
   1. [Parcourir rapidement les modifications pour une vue d'ensemble](#skim-changes-for-an-overview)
   1. [Examiner chaque fichier en profondeur](#examine-each-file-in-depth)
   1. [Tester le code](#test-the-code)
   1. [Vérifier les pipelines](#check-the-pipelines)
   1. [Considérations pour la re-révision](#re-review-considerations)
   1. [Penser à la vue d'ensemble](#think-about-the-big-picture)
1. [Terminer votre révision](#finish-your-review)
   1. [Rédiger vos commentaires de révision](#write-your-review-comments)
   1. [Résumer votre révision](#summarize-your-review)
1. [Effectuer les tâches de nettoyage](#perform-cleanup-tasks)

## Accéder à la merge request {#go-to-the-merge-request}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. L'une ou l'autre des options :
   - Appuyez sur <kbd>Shift</kbd>+<kbd>r</kbd> pour accéder à votre page **Requêtes de fusion**.
   - Dans le coin supérieur droit, sélectionnez **Requêtes de fusion** ({{< icon name="merge-request" >}}).

## Comprendre la structure des merge requests {#understand-the-structure-of-merge-requests}

Les merge requests disposent d'un menu secondaire avec quatre options. Vous utilisez ces zones d'une merge request à différents moments au cours de votre révision :

![Merge request avec l'onglet Vue d'ensemble sélectionné, affichant le titre, le demandeur et le statut, ainsi que les onglets Validation, Pipelines et Modifications](img/top_bar_v17_0.png)

- **Vue d'ensemble** : la description de la merge request, un rapport sur sa fusionnabilité actuelle, une zone **Activité** avec des commentaires et une barre latérale contenant plus d'informations.
- **Validation** : une liste des commits de cette merge request, du plus récent au plus ancien.
- **Pipelines** : une liste des pipelines CI/CD exécutés sur le contenu de cette merge request.
- **Modifications** : un diff des modifications proposées dans cette merge request, affichant les lignes supprimées, ajoutées et modifiées.

La barre latérale de l'onglet **Vue d'ensemble** contient des métadonnées importantes sur la merge request elle-même : l'assigné, le relecteur, les labels, le jalon et le suivi du temps.

## Obtenir une vue d'ensemble de la merge request {#get-a-high-level-view-of-the-merge-request}

Avant de vous lancer dans la revue de code, vous devez évaluer la merge request à un niveau général. Comprenez le contexte et l'objectif de la merge request : ce qu'elle cherche à accomplir et pourquoi. Comparez ces besoins à vos compétences, tout en vous posant ces questions :

1. Quelle est l'histoire derrière cette merge request ? Ai-je suffisamment de connaissances dans ce domaine pour effectuer une révision réfléchie ?
1. Quel type et quelle profondeur de révision ont été demandés ? Par exemple, une correction de bug à portée limitée et une révision architecturale approfondie ont probablement des attentes de révision très différentes.
1. Êtes-vous la bonne personne pour effectuer la revue de code de ce travail ? Le type de révision requis correspond-il à vos compétences et aptitudes ?

Commencez par examiner la description de la merge request. Elle doit correspondre à la solution d'un problème ou à une demande de fonctionnalité dans un ticket.

- Qui est l'auteur ? Connaissez-vous le travail de cette personne ? Si vous connaissez cette personne, sur quelle partie de la base de code travaille-t-elle habituellement ? Plus tard, votre connaissance de l'auteur vous aidera à évaluer le niveau de scrutin à appliquer à ses modifications.
- Quel est l'objectif ? Lisez la description pour comprendre l'intention de l'auteur.
- Est-ce un brouillon ? Les brouillons sont souvent des solutions incomplètes ou théoriques. Une merge request en brouillon peut nécessiter un niveau de scrutin différent de celui des merge requests entièrement finalisées.
- Comment reproduire le problème ? La description explique-t-elle comment reproduire le problème, tester les modifications ou essayer la nouvelle fonctionnalité ? Inclut-elle des captures d'écran pour vous guider ?

Sous la description, vérifiez le widget de merge request pour comprendre le statut actuel de ce travail. Cet exemple montre un widget de fusion pour une merge request à laquelle il manque des approbations, qui est encore en mode brouillon et qui contient des fils de discussion ouverts :

![Widget de fusion affichant un statut bloqué avec trois vérifications échouées : approbations manquantes, mode brouillon et fils de discussion ouverts](img/widget_v17_0.png)

- Contient-elle un lien croisé vers un ticket ? Vérifiez la description et le widget de fusion pour trouver des liens vers d'autres tickets. Certaines merge requests sont simples, mais d'autres vous obligent à lire le ticket correspondant pour comprendre comment cette merge request a vu le jour. Les merge requests plus complexes doivent renvoyer vers des tickets contenant toutes les informations nécessaires.
- Quel est le statut du pipeline ? Le pipeline est-il vert ? Les pipelines rouges indiquent des problèmes. Si vous voyez des pipelines incomplets ou annulés, vous ne pouvez pas encore évaluer la fusionnabilité complète du travail.

### Vérifier les tickets liés {#check-related-issues}

Si des tickets liés existent et que la merge request vous semble suffisamment complexe pour nécessiter plus d'informations, parcourez les descriptions des tickets.

- Le problème et la solution sont-ils bien séparés ? Le ticket doit décrire et analyser le problème, et la merge request doit se concentrer sur la solution.
- L'auteur de la merge request est-il impliqué dans le ticket ? Tout au long du processus de révision, réfléchissez à qui a contribué à définir le problème (ou la fonctionnalité). Idéalement, ces personnes sont également impliquées dans la merge request.

### Vérifier la barre latérale {#check-the-sidebar}

- Quels labels possède-t-elle ? Les labels peuvent fournir des indices sur le contenu de la merge request. Selon le workflow de votre équipe, des labels incomplets ou manquants peuvent être anodins ou indiquer que cette merge request manque d'informations complètes.
  - Si les labels correspondent à votre domaine d'expertise, vous êtes probablement un bon candidat pour effectuer la revue de code de cette merge request.
  - Si les labels correspondent à des domaines d'expertise que vous ne maîtrisez pas, vous devrez peut-être réattribuer la merge request à un autre relecteur.
  - Ajoutez les labels attendus par votre workflow.

  Dans cet exemple, même si les labels exacts ne vous sont pas familiers, vous pouvez déterminer que cette merge request concerne un bug de base de données :

  ![La section Labels d'une merge request, affichant 10 labels de différentes couleurs, dont « database » et « type: bug »](img/labels_v17_0.png)
- Qui sont les relecteurs ? Parcourez les noms dans la liste des relecteurs. Correspondent-ils au type de travail que vous attendez, en fonction de la description et (éventuellement) des labels ? Tenez compte à la fois des personnes présentes et absentes. Que vous indiquent ces noms sur l'avancement de cette merge request dans son cycle de révision ? Avez-vous besoin d'ajouter ou de supprimer des personnes ?
- Des relecteurs ont-ils déjà approuvé ? Si vous connaissez ces relecteurs et leurs domaines d'expertise, vous pouvez avoir une idée des aspects des modifications proposées qui nécessitent votre attention.

  Dans cet exemple, Thomas et Nick sont tous les deux relecteurs. Thomas n'a pas encore effectué la revue de code ({{< no >}}) de la merge request. Nick a effectué la revue de code et approuvé ({{< yes >}}) :

  ![La section Relecteurs d'une merge request, listant 2 relecteurs](img/reviewer_list_v17_0.png)

### Vérifier les commentaires {#check-the-comments}

Sur la page **Vue d'ensemble**, lisez les commentaires laissés par l'auteur et les autres personnes. Gardez ces discussions à l'esprit pendant que vous lisez les modifications du code.

Voyez-vous des traces de révisions précédentes dans les commentaires ? Un grand nombre de commentaires peut influencer la profondeur à laquelle vous souhaitez effectuer la revue de code de ce travail.

## Lire les modifications du code {#read-the-code-changes}

Vous êtes maintenant prêt à lire les modifications proposées. Pour les merge requests volumineuses, parcourez rapidement les modifications avant de vous y plonger. Construisez votre compréhension de ce à quoi vous attendre avant de commencer à lire les modifications ligne par ligne.

> [!note]
> Les diffs affichés dans l'onglet **Modifications** sont riches en informations. Pour apprendre à tirer le meilleur parti de cette page, consultez [Les modifications dans les merge requests](../../user/project/merge_requests/changes.md).

### Parcourir rapidement les modifications pour une vue d'ensemble {#skim-changes-for-an-overview}

Lorsque vous ouvrez la page **Modifications** pour la première fois, concentrez-vous d'abord sur les détails généraux :

- Quels fichiers ont été modifiés ? Développez l'explorateur de fichiers ({{< icon name="file-tree" >}}) pour voir la liste des fichiers modifiés. Connaissez-vous ces fichiers ? Dans quelle partie de la base de code ces fichiers se trouvent-ils ?

  ![Explorateur de fichiers affichant 2 fichiers modifiés avec leurs emplacements et les indicateurs de modification de lignes](img/file_tree_v17_0.png)
- La liste des fichiers correspond-elle à vos attentes ? Vous avez déjà lu la description de la merge request. Ce sont-ils les fichiers que vous vous attendiez à voir modifiés pour ce type de travail ? Portez une attention particulière aux modifications apportées à des fichiers inattendus, ou si des modifications que vous espériez voir sont manquantes.
- Des lignes ont-elles été ajoutées, supprimées ou modifiées ? Ces chiffres vous indiquent le type de travail à attendre lors de votre lecture approfondie : une nouvelle fonctionnalité, une fonctionnalité supprimée ou des modifications de comportement ?
- Des tests ont-ils été modifiés ? Certains des fichiers font-ils partie de votre suite de tests ? Si ce n'est pas le cas, vous devrez peut-être inciter l'auteur à mettre à jour les tests.
- Des feature flags sont-ils utilisés ? Si vous voyez des feature flags, notez de vérifier leur utilisation lors de votre lecture approfondie.

Lorsque vous avez terminé de parcourir rapidement les modifications, vous êtes prêt à les lire ligne par ligne !

### Examiner chaque fichier en profondeur {#examine-each-file-in-depth}

Vous avez maintenant une idée générale des modifications que contient cette merge request. Il est temps de vous y plonger et de lire les modifications dans leur intégralité. Restez attentif à vos points forts et à vos points faibles en termes de connaissances. Connaissez-vous bien ce projet ? Les modifications sont-elles rédigées dans un langage avec lequel vous êtes à l'aise ?

- Les modifications sont-elles claires et compréhensibles ?
- Des feature flags sont-ils utilisés ? Les modifications testent-elles la présence ou l'absence du feature flag ? Assurez-vous que les modifications soumises à un feature flag ne fuient pas accidentellement lorsque le flag est désactivé.
- Est-ce performant ? Êtes-vous à l'aise pour tester les performances vous-même, ou devez-vous ajouter un relecteur ayant des connaissances plus approfondies en matière de performances ?
- Peut-on le simplifier ?
- Prend-il en compte les cas limites ?
- Est-il correctement commenté et documenté ? Un bon code est maintenable par d'autres personnes, pas seulement par l'auteur. L'auteur a-t-il fourni suffisamment d'explications pour rendre ce travail maintenable ?
- Respecte-t-il les conventions de style de votre équipe ?
- Est-il rétrocompatible ? Ce travail constitue-t-il un changement cassant ? Pourrait-il provoquer une perte de données ?
- Les problèmes de sécurité sont-ils pris en compte ? Les modifications se trouvent-elles dans une zone de votre projet présentant des préoccupations de sécurité particulières ? Gèrent-elles les données sensibles de manière appropriée ? Acceptent-elles des données saisies par l'utilisateur et ont-elles été assainies ? Devez-vous ajouter un relecteur ayant davantage de connaissances en matière de sécurité ?
- Des instructions de débogage ont-elles été laissées en place ?

Les différents types de modifications ont des effets différents sur votre base de code. Réfléchissez en termes généraux :

- Lignes ajoutées : le nouveau code ne doit pas modifier le comportement existant. Les nouveaux comportements sont-ils testés ? Les tests sont-ils suffisamment granulaires ?
- Lignes supprimées : la suppression est-elle propre et complète ? Le code supprimé et les tests correspondent-ils l'un à l'autre en termes de portée ? Assurez-vous qu'aucun stub partiel n'est laissé dans l'un ou l'autre endroit.
- Lignes modifiées : si les lignes ajoutées et supprimées sont à peu près équivalentes, les modifications constituent-elles un refactoring du code existant ? Pour un refactoring, comprenez-vous ce que faisait le code précédent et comment le nouveau code s'y prend différemment ? Les modifications de comportement correspondent-elles à l'intention déclarée par l'auteur dans la description ? Les tests fonctionnent-ils toujours correctement ?

### Tester le code {#test-the-code}

Malheureusement, nous ne pouvons pas vous donner beaucoup de conseils ici. Chaque projet est différent ! Sans connaître votre application de première main, nous ne pouvons pas vous dire comment tester les modifications, mais nous pouvons vous proposer quelques questions à considérer :

- Cela fonctionne-t-il ? C'est une question trompeusement simple, mais il est important de la garder à l'esprit. Le code peut être laid, alambiqué et non documenté, mais fonctionner quand même.
- À quel stade en est le processus de révision ? Êtes-vous en début ou en fin de processus de révision ? Êtes-vous un spécialiste ?

  - Les relecteurs en début de processus doivent vérifier que le code fonctionne comme l'auteur l'indique. Cela évite que davantage de personnes consacrent du temps à du code qui ne peut pas ou ne doit pas être fusionné.
  - Les relecteurs en fin de processus ne sont peut-être pas impliqués dans la vérification du bon fonctionnement de la fonctionnalité, mais peuvent plutôt se concentrer davantage sur le style et la maintenabilité.
  - Les relecteurs spécialisés peuvent n'examiner que certaines parties des merge requests, sans vérifier si l'ensemble de la merge request fonctionne comme prévu.

Pendant que vous testez le code, vous devez également vérifier le statut du pipeline. Bien que vous n'ayez pas encore rédigé de commentaires de révision, vous êtes presque prêt.

### Vérifier les pipelines {#check-the-pipelines}

Accédez à l'onglet **Pipelines** de la merge request et vérifiez le statut du pipeline. N'approuvez la merge request que si le pipeline a réussi. Dans cet exemple, plusieurs jobs ont échoué :

![Widget de statut du pipeline affichant les jobs réussis et échoués dans un pipeline de résultat de fusion](img/failed_pipeline_v17_0.png)

- Tous les tests attendus ont-ils été exécutés ? Assurez-vous que le pipeline n'est pas seulement vert, mais complet.
- Des tests ont-ils échoué ? Développez **Job ayant échoué** pour voir quels tests, le cas échéant, ont échoué.
- Que s'est-il passé dans chaque job ayant échoué ? Sélectionnez chaque job ayant échoué. Faites défiler la sortie en recherchant les mentions d'échecs, d'erreurs et de lignes marquées en rouge. Lorsque vous rédigez vos commentaires de révision, vous souhaitez aider l'auteur à comprendre ce qui doit être corrigé et comment le faire.
- Les échecs sont-ils liés aux modifications ? Si les échecs semblent sans rapport, envisagez de relancer le job ou le pipeline.

### Considérations pour la re-révision {#re-review-considerations}

Parfois, les revues de code des merge requests ne sont pas simples et nécessitent des échanges entre l'assigné et les relecteurs. Si vous effectuez une re-révision, accédez à la page **Validation** de cette merge request et lisez le contenu des commits ajoutés depuis votre dernière révision.

Ces commits répondent-ils à vos préoccupations soulevées lors de votre révision initiale ?

### Penser à la vue d'ensemble {#think-about-the-big-picture}

Vous avez maintenant effectué le travail préparatoire pour une révision réfléchie et utile. Lorsque vous avez parcouru la merge request pour la première fois, vous n'aviez pas une connaissance complète des modifications au niveau des lignes. Maintenant, vous l'avez ! Avant de commencer à écrire, prenez du recul par rapport à la vue ligne par ligne de la merge request et réfléchissez-y à nouveau de manière globale. Vous savez maintenant ce que la merge request cherche à accomplir et comment elle y parvient.

- Les modifications de la merge request correspondent-elles à la portée prévue ? Si ce n'est pas le cas, demandez-vous si le travail doit être simplifié ou divisé en plusieurs merge requests. Soyez honnête quant à votre propre périmètre de connaissances et à vos limites.
- Détectez-vous des [mauvaises odeurs de code](https://martinfowler.com/bliki/CodeSmell.html) ? Si quelque chose que vous voyez n'est pas un bug, mais pointe vers de futurs problèmes de qualité, de maintenabilité ou de sécurité, soyez vigilant. Faites confiance à votre instinct si quelque chose dans les modifications vous semble erroné, obscur ou mal réalisé. Le code peut être techniquement correct, mais contenir des faiblesses susceptibles de causer des problèmes à l'avenir.

Les meilleures revues de code les plus utiles ne se concentrent pas uniquement sur les corrections ligne par ligne. Elles tiennent également compte des préoccupations à long terme, comme la maintenabilité et la dette technique.

## Terminer votre révision {#finish-your-review}

Il est temps de donner votre avis !

Lorsque vous débutez dans la revue de code des merge requests, vous pourriez être surpris du temps que vous passez à réfléchir avant de rédiger votre premier commentaire. À mesure que vous vous familiarisez avec une base de code, vous comprendrez les nouvelles merge requests plus rapidement. Cependant, vous commencerez probablement aussi à prendre en charge des révisions plus complexes.

### Rédiger vos commentaires de révision {#write-your-review-comments}

La fonctionnalité **Démarrer une révision** vous permet de consigner vos réflexions dans des commentaires en attente. Ces commentaires ne sont visibles par personne d'autre tant que vous n'avez pas soumis votre révision. Cela évite la surcharge de messages pour vos destinataires et vous donne la possibilité de relire (et de modifier) vos mots avant de les publier.

N'oubliez pas d'être constructif et bienveillant. La structure des [commentaires conventionnels](https://conventionalcomments.org/) peut vous aider à rédiger des commentaires à la fois réfléchis et constructifs.

Commencez par rédiger les commentaires que vous souhaitez associer à des lignes ou fichiers spécifiques :

1. Sélectionnez l'onglet **Modifications**.
1. Lorsque vous trouvez des lignes sur lesquelles vous souhaitez poser des questions ou fournir des retours, sélectionnez **Ajouter un commentaire à cette ligne** ({{< icon name="comment" >}}) dans la marge. Cela développe les lignes du diff et affiche une zone de commentaire.
1. Vous pouvez également [sélectionner plusieurs lignes](../../user/project/merge_requests/reviews/suggestions.md#multi-line-suggestions) ou sélectionner un fichier entier sur lequel commenter :

   ![Interface de diff de code affichant un bouton en forme de bulle de dialogue à côté d'un numéro de ligne avec une infobulle pour ajouter un commentaire sur une ou plusieurs lignes](img/comment_on_any_diff_line_v16_6.png)
1. Dans la zone de texte, rédigez votre premier commentaire. Pour garder vos commentaires privés jusqu'à la fin de votre révision, sélectionnez **Démarrer une révision** sous votre commentaire.
1. [Fournissez des suggestions](../../user/project/merge_requests/reviews/suggestions.md) lorsque les corrections sont faciles à rédiger pour vous, ou si vous souhaitez montrer à l'auteur une meilleure approche. Si les modifications du code sont trop importantes ou complexes pour le format de suggestion, laissez un commentaire demandant des modifications.
1. Continuez à commenter sur les fichiers et les lignes de code individuelles. Après chaque commentaire, sélectionnez **Ajouter à la revue de code**.

Au fil de votre travail, vous pouvez utiliser des [actions rapides](../../user/project/quick_actions.md), comme `/label` ou `/assign_reviewer`, dans vos commentaires de révision. Vos commentaires en attente affichent vos actions demandées, mais les actions ne sont pas exécutées tant que vous n'avez pas soumis votre révision. (Plus tard, vous pouvez également soumettre votre révision avec l'action rapide `/submit_review` !)

### Résumer votre révision {#summarize-your-review}

Vous avez ajouté vos retours spécifiques aux fichiers et aux lignes, et vous êtes maintenant prêt à résumer votre révision. Il est temps de réfléchir de manière globale, une dernière fois.

1. Retournez à la page **Vue d'ensemble** de la merge request.
1. Parcourez vos commentaires en attente. Ils doivent être utiles, réfléchis, bienveillants et, surtout, exploitables. Avez-vous indiqué à l'auteur une prochaine étape évidente pour corriger les problèmes que vous avez trouvés ?
1. Réfléchissez à votre ton. Enseignez-vous, débattez-vous ou discutez-vous ? Vos commentaires atteignent-ils votre objectif ? Si vous étiez l'auteur, sauriez-vous quoi faire ensuite ? Renforcez les bons comportements et incitez l'auteur à s'éloigner des mauvais comportements.
1. Vos commentaires ont-ils toujours du sens ? Dans les merge requests volumineuses, il se peut que certains commentaires ne soient plus utiles, ou que certaines questions que vous aviez aient été répondues entre-temps.
1. Démarrez des fils de discussion pour les retours généraux. Assurez-vous que les éléments sans rapport ne sont pas regroupés dans le même commentaire, afin que lorsque les fils de discussion sont résolus, les retours non traités ne soient pas masqués. Quelques sujets possibles :
   - Diviser les grandes fonctions en fonctions plus petites à usage unique.
   - Utiliser des noms de variables significatifs.
   - Ajouter plus de commentaires pour expliquer le code complexe.
   - Vérifier les cas limites et les erreurs.
1. Démarrez un nouveau fil de discussion pour votre commentaire de synthèse. Assurez-vous de mentionner le nom d'utilisateur de l'auteur, au cas où il travaillerait à partir d'éléments de la liste de tâches. Indiquez clairement :
   - Quel est votre constat général ?
   - Avez-vous terminé la révision, ou souhaitez-vous revoir cette merge request après que d'autres travaux ont été effectués ?
1. En haut à droite, sélectionnez **Votre révision** pour afficher les détails de votre révision :

   ![Le panneau de révision, affichant une révision en cours. Il contient un commentaire de révision sur une seule ligne et un commentaire couvrant deux lignes de code.](../../user/project/merge_requests/reviews/img/review_drawer_v18_3.png)
1. Relisez vos commentaires en attente. Modifiez-les si nécessaire.
1. Sélectionnez le résultat de votre révision.

   - **Approuver** : laissez vos retours et approuvez les modifications.
   - **Commentaire** : laissez des retours généraux sans approbation explicite ni demande de modification.
   - **Demander des modifications** : bloquez la fusion de la merge request jusqu'à ce que l'auteur prenne en compte vos retours.

1. Facultatif. Rédigez un résumé de votre révision. Les utilisateurs de GitLab Premium et Ultimate peuvent sélectionner **Ajouter un résumé** ({{< icon name="tanuki-ai" >}}) pour créer un résumé à leur place. Incluez toutes les actions rapides que vous souhaitez exécuter.

Vous pouvez également utiliser [l'action rapide `/submit_review`](../../user/project/quick_actions.md#submit_review) dans le texte d'un commentaire hors révision.

Si vous [approuvez une merge request](../../user/project/merge_requests/approvals/_index.md#approve-a-merge-request) et apparaissez dans la liste des relecteurs, une coche verte {{< icon name="check-circle-filled" >}} s'affiche à côté de votre nom.

## Effectuer les tâches de nettoyage {#perform-cleanup-tasks}

Après avoir fourni vos retours, faites le ménage.

- Assurez-vous que tous les commentaires en attente ont été soumis.
- Mettez à jour les labels et le jalon.
- Vérifiez les exigences d'approbation.
  - Chaque type de travail (backend, frontend, documentation) dans la merge request a-t-il été révisé par la bonne personne ?
  - Si d'autres révisions sont nécessaires, mentionnez les noms d'utilisateur des prochains relecteurs et ajoutez-les en tant que relecteurs.
- Vérifiez le widget de fusion.
  - Traitez les blocages que vous pouvez résoudre et assignez des utilisateurs pour aider avec ceux que vous ne pouvez pas.
  - Ajoutez les propriétaires du code nécessaires pour la révision.
- Cette merge request est-elle prête à être fusionnée ? Si la merge request a été entièrement révisée et approuvée, assignez-la à un mainteneur pour la fusion !

## Sujets connexes {#related-topics}

- [Les commentaires conventionnels](https://conventionalcomments.org/) fournissent une structure utile pour les commentaires.
- [Conseils pour une revue de code efficace](https://about.gitlab.com/blog/efficient-code-review-tips/)
