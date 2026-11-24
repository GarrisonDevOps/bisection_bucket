---
stage: Security Risk Management
group: Security Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: "Résoudre les vulnérabilités avec l'IA"
---

{{< details >}}

- Édition : GitLab Ultimate
- Module d'extension : GitLab Duo Enterprise, GitLab Duo avec Amazon Q
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="Informations sur le modèle" >}}

- [LLM par défaut](../../gitlab_duo/model_selection.md#default-models)
- LLM pour Amazon Q : Amazon Q Developer
- Disponible sur [GitLab Duo avec des modèles auto-hébergés](../../../administration/gitlab_duo_self_hosted/_index.md) : Oui

{{< /collapsible >}}

GitLab Duo Vulnerability Resolution vous aide à résoudre automatiquement les vulnérabilités de sécurité.

<i class="fa fa-youtube-play youtube" aria-hidden="true"></i> [Visionner une présentation](https://www.youtube.com/watch?v=VJmsw_C125E&list=PLFGfElNsQthZGazU1ZdfDpegu0HflunXW)

Pour plus d'informations, consultez [comment activer toutes les fonctionnalités GitLab Duo](../../gitlab_duo/turn_on_off.md).

## Utiliser l'assistance IA de manière responsable {#use-ai-assistance-responsibly}

Comme pour tous les systèmes basés sur l'IA, nous ne pouvons pas garantir que le grand modèle de langage produit des résultats corrects à chaque fois. Vous devriez toujours examiner la modification proposée avant de l'intégrer. Pendant cet examen, vérifiez que :

- le fonctionnement existant de votre application est préservé ;
- la vulnérabilité est résolue conformément aux normes de votre organisation.

## Vulnérabilités prises en charge par Vulnerability Resolution {#supported-vulnerabilities-for-vulnerability-resolution}

Pour assurer la qualité des résolutions suggérées, Vulnerability Resolution n'est disponible que pour un ensemble défini de vulnérabilités. Le système s'appuie sur l'identifiant Common Weakness Enumeration (CWE) de la vulnérabilité pour déterminer si Vulnerability Resolution doit être proposée.

Nous avons sélectionné l'ensemble actuel de vulnérabilités sur la base de tests effectués par des systèmes automatisés et des experts en sécurité. Nous travaillons activement à l'élargissement de la couverture à davantage de types de vulnérabilités.

<details><summary style="color:#5943b6; margin-top: 1em;"><a>Consulter la liste complète des CWE pris en charge par Vulnerability Resolution</a></summary>

<ul>
  <li>CWE-23 : Relative Path Traversal</li>
  <li>CWE-73 : External Control of File Name or Path</li>
  <li>CWE-78 : Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')</li>
  <li>CWE-80 : Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)</li>
  <li>CWE-89 : Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')</li>
  <li>CWE-116 : Improper Encoding or Escaping of Output</li>
  <li>CWE-118 : Incorrect Access of Indexable Resource ('Range Error')</li>
  <li>CWE-119 : Improper Restriction of Operations within the Bounds of a Memory Buffer</li>
  <li>CWE-120 : Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')</li>
  <li>CWE-126 : Buffer Over-read</li>
  <li>CWE-190 : Integer Overflow or Wraparound</li>
  <li>CWE-200 : Exposure of Sensitive Information to an Unauthorized Actor</li>
  <li>CWE-208 : Observable Timing Discrepancy</li>
  <li>CWE-209 : Generation of Error Message Containing Sensitive Information</li>
  <li>CWE-272 : Least Privilege Violation</li>
  <li>CWE-287 : Improper Authentication</li>
  <li>CWE-295 : Improper Certificate Validation</li>
  <li>CWE-297 : Improper Validation of Certificate with Host Mismatch</li>
  <li>CWE-305 : Authentication Bypass by Primary Weakness</li>
  <li>CWE-310 : Cryptographic Issues</li>
  <li>CWE-311 : Missing Encryption of Sensitive Data</li>
  <li>CWE-323 : Reusing a Nonce, Key Pair in Encryption</li>
  <li>CWE-327 : Use of a Broken or Risky Cryptographic Algorithm</li>
  <li>CWE-328 : Use of Weak Hash</li>
  <li>CWE-330 : Use of Insufficiently Random Values</li>
  <li>CWE-338 : Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)</li>
  <li>CWE-345 : Insufficient Verification of Data Authenticity</li>
  <li>CWE-346 : Origin Validation Error</li>
  <li>CWE-352 : Cross-Site Request Forgery</li>
  <li>CWE-362 : Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')</li>
  <li>CWE-369 : Divide By Zero</li>
  <li>CWE-377 : Insecure Temporary File</li>
  <li>CWE-378 : Creation of Temporary File With Insecure Permissions</li>
  <li>CWE-400 : Uncontrolled Resource Consumption</li>
  <li>CWE-489 : Active Debug Code</li>
  <li>CWE-521 : Weak Password Requirements</li>
  <li>CWE-539 : Use of Persistent Cookies Containing Sensitive Information</li>
  <li>CWE-599 : Missing Validation of OpenSSL Certificate</li>
  <li>CWE-611 : Improper Restriction of XML External Entity Reference</li>
  <li>CWE-676 : Use of potentially dangerous function</li>
  <li>CWE-704 : Incorrect Type Conversion or Cast</li>
  <li>CWE-754 : Improper Check for Unusual or Exceptional Conditions</li>
  <li>CWE-770 : Allocation of Resources Without Limits or Throttling</li>
  <li>CWE-1004 : Sensitive Cookie Without 'HttpOnly' Flag</li>
  <li>CWE-1275 : Sensitive Cookie with Improper SameSite Attribute</li>
</ul>
</details>

## Données partagées avec des API d'IA tierces dans le cadre de Vulnerability Resolution {#data-shared-with-third-party-ai-apis-for-vulnerability-resolution}

Les données suivantes sont partagées avec des API d'IA tierces :

- Nom de la vulnérabilité
- Description de la vulnérabilité
- Identifiants (CWE, OWASP)
- Fichier complet contenant les lignes de code vulnérables
- Lignes de code vulnérables (numéros de ligne)

## Workflows {#workflows}

Vulnerability Resolution est disponible dans les workflows suivants :

- Résoudre les vulnérabilités existantes depuis le rapport de vulnérabilités.
- Résoudre les vulnérabilités dans le contexte d'une merge request.

### Résoudre une vulnérabilité depuis le rapport de vulnérabilités {#resolve-a-vulnerability-from-the-vulnerability-report}

{{< history >}}

- Résoudre une vulnérabilité depuis le rapport de vulnérabilités :
  - [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/10779) dans GitLab 16.7 en tant que [version expérimentale](../../../policy/development_stages_support.md#experiment) sur GitLab.com.
  - Passage en version bêta dans GitLab 17.3.
  - Obligation de disposer du module d'extension GitLab Duo à partir de GitLab 17.6.
- Icône d'activité de Vulnerability Resolution :
  - [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/15036) dans GitLab 17.5 avec le feature flag [`vulnerability_report_vr_badge`](https://gitlab.com/gitlab-org/gitlab/-/issues/486549). Désactivé par défaut.
  - [Activée par défaut](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171718) dans GitLab 17.6.
  - [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/503568) dans GitLab 18.0. Suppression du feature flag `vulnerability_report_vr_badge`.

{{< /history >}}

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.
- La vulnérabilité doit être un résultat SAST provenant d'un analyseur pris en charge :
  - Tout [analyseur pris en charge par GitLab](../sast/analyzers.md).
  - Un scanner SAST tiers correctement intégré qui indique, pour chaque vulnérabilité, son emplacement et son identifiant CWE.
- La vulnérabilité doit relever d'un [type pris en charge](#supported-vulnerabilities-for-vulnerability-resolution).

Pour résoudre une vulnérabilité depuis le rapport de vulnérabilités :

1. Dans la barre latérale gauche, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Sélectionnez **Sécuriser** > **Rapport de vulnérabilités**.
1. Facultatif. Pour supprimer les filtres par défaut, sélectionnez **Effacer** ({{< icon name="clear" >}}).
1. Sélectionnez la barre de filtres située au-dessus de la liste des vulnérabilités.
1. Dans la liste déroulante qui s'affiche, sélectionnez **Activité**, puis, dans la catégorie **GitLab Duo (IA)**, sélectionnez **Résolution de vulnérabilités disponible**.
1. Cliquez en dehors du champ de filtre. Les totaux de vulnérabilités par niveau de gravité et la liste des vulnérabilités correspondantes sont mis à jour.
1. Sélectionnez la vulnérabilité SAST à résoudre.
   - Une icône bleue s'affiche à côté des vulnérabilités compatibles avec Vulnerability Resolution.
1. Dans le coin supérieur droit, sélectionnez **Résoudre grâce à l'IA**. Si ce bouton n'est pas affiché, sélectionnez **Actions IA**, puis sélectionnez **Résoudre grâce à l'IA**.
   > [!warning]
   > Si ce projet est un projet public, sachez que la création d'une merge request exposera publiquement la vulnérabilité et la résolution proposée. Pour créer la merge request de manière privée, [créez une duplication privée](../../project/merge_requests/confidential.md), puis répétez ce processus.
1. Ajoutez un commit supplémentaire à la merge request. Cela déclenche l'exécution d'un nouveau pipeline.
1. Une fois le pipeline terminé, confirmez dans l'[onglet de sécurité du pipeline](../detect/security_scanning_results.md) que la vulnérabilité n'apparaît plus.
1. Dans le rapport de vulnérabilités, [mettez à jour manuellement la vulnérabilité](../vulnerability_report/_index.md#change-status-of-vulnerabilities).

Une merge request contenant les suggestions de remédiation générées par l'IA s'ouvre. Examinez les modifications suggérées, puis traitez la merge request selon votre workflow standard.

### Résoudre une vulnérabilité dans une merge request {#resolve-a-vulnerability-in-a-merge-request}

{{< history >}}

- [Introduction](https://gitlab.com/groups/gitlab-org/-/work_items/14862) dans GitLab 17.6.
- [Activation par défaut](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/175150) dans GitLab 17.7.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185452) dans GitLab 17.11. Suppression du feature flag `resolve_vulnerability_in_mr`.

{{< /history >}}

Vous pouvez utiliser GitLab Duo Vulnerability Resolution dans une merge request pour corriger les vulnérabilités avant leur fusion. Vulnerability Resolution crée automatiquement un commentaire de suggestion de merge request qui résout la détection de vulnérabilité.

Prérequis :

- Disposer du rôle Chargé de maintenance ou Propriétaire pour le projet.
- La vulnérabilité doit être un résultat SAST provenant d'un analyseur pris en charge :
  - Tout [analyseur pris en charge par GitLab](../sast/analyzers.md).
  - Un scanner SAST tiers correctement intégré qui indique, pour chaque vulnérabilité, son emplacement et son identifiant CWE.
- La vulnérabilité doit relever d'un [type pris en charge](#supported-vulnerabilities-for-vulnerability-resolution).

Pour résoudre une détection de vulnérabilité :

1. Dans la barre latérale gauche, sélectionnez **Rechercher ou accéder à** et repérez votre projet.
1. Sélectionnez **Requêtes de fusion**.
1. Sélectionnez une merge request.
   - Les détections de vulnérabilités prises en charge par Vulnerability Resolution sont indiquées par l'icône IA tanuki ({{< icon name="tanuki-ai" >}}).
1. Sélectionnez les résultats pris en charge pour ouvrir la boîte de dialogue du résultat de sécurité.
1. Dans le coin inférieur droit, sélectionnez **Résoudre grâce à l'IA**.

   Un commentaire contenant les suggestions de remédiation générées par l'IA s'ouvre dans la merge request.
1. Examinez les modifications suggérées, puis appliquez la suggestion dans la merge request selon votre workflow standard.

## Dépannage {#troubleshooting}

Vulnerability Resolution ne peut pas toujours générer une proposition de correctif. Les causes courantes sont les suivantes :

- Faux positif détecté :
  - Avant de proposer un correctif, le modèle d'IA évalue la validité de la vulnérabilité. Il peut estimer que la vulnérabilité n'est pas avérée ou qu'elle ne justifie pas de correctif.
  - Cela peut se produire si la vulnérabilité se trouve dans du code de test. Votre organisation peut néanmoins choisir de corriger les vulnérabilités situées dans du code de test, mais les modèles les considèrent parfois comme des faux positifs.
  - Si vous estimez que la vulnérabilité est un faux positif ou qu'elle ne justifie pas de correctif, vous devriez [rejeter la vulnérabilité](../vulnerabilities/_index.md#vulnerability-status-values) et [sélectionner une raison correspondante](../vulnerabilities/_index.md#vulnerability-dismissal-reasons).
    - Pour personnaliser votre configuration SAST ou signaler un problème lié à une règle GitLab SAST, consultez [les règles SAST](../sast/rules.md).
- Erreur temporaire ou inattendue :
  - le message d'erreur peut mentionner `an unexpected error has occurred`, `the upstream AI provider request timed out`, `something went wrong` ou une cause similaire.
  - Des problèmes temporaires affectant le fournisseur d'IA ou GitLab Duo peuvent provoquer ces erreurs.
  - Une nouvelle demande peut aboutir. Vous pouvez donc essayer une nouvelle fois de résoudre la vulnérabilité.
  - Si ces erreurs persistent, contactez GitLab pour obtenir de l'aide.
- Erreur `Resolution target could not be found in the merge request, unable to create suggestion` :
  - Cette erreur peut se produire si aucun pipeline complet d'analyse de sécurité n'a été exécuté sur la branche cible. Consultez la [documentation sur les merge requests](../detect/security_scanning_results.md).
