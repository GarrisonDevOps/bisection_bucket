---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Pourquoi vous devriez signer vos commits GitLab de manière cryptographique et comment vérifier les commits signés.
title: Commits signés
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Lorsque vous ajoutez une signature numérique à votre commit, vous apportez une assurance supplémentaire que le commit provient bien de vous et non d'un imposteur. Une signature numérique est une sortie cryptographique utilisée pour vérifier l'authenticité.

Il est important de comprendre la différence entre les commits signés et les commits vérifiés :

- Les commits signés possèdent une signature cryptographique qui prouve l'intégrité et l'authenticité du commit. La signature est créée à l'aide d'une clé privée.
- Les commits vérifiés possèdent des signatures que GitLab peut valider par rapport à une clé publique connue stockée dans le profil GitLab d'un utilisateur.

Si GitLab peut vérifier l'identité du validateur à l'aide d'une clé publique, le commit est marqué **Vérifié** dans l'interface GitLab.

> [!note]
> Les champs validateur et auteur sont distincts dans Git. L'auteur écrit le commit, et le validateur l'applique. La signature du commit vérifie uniquement l'identité du validateur.

GitLab vérifie les signatures des commits et des tags. Les méthodes de signature suivantes sont prises en charge :

- [Clé SSH](ssh.md)
- [Clé GPG](gpg.md)
- [Certificat X.509](x509.md)

## Vérifier les commits {#verify-commits}

Pour examiner les commits d'une merge request ou d'un projet entier et vérifier qu'ils sont signés :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Pour examiner les commits :
   - Pour un projet, sélectionnez **Code** > **Validation**.
   - Pour une merge request :
     1. Dans la barre latérale gauche, sélectionnez **Code** > **Requêtes de fusion**, puis sélectionnez votre merge request.
     1. Sélectionnez **Validation**.
1. Identifiez le commit que vous souhaitez examiner. En fonction du statut de vérification de la signature, les commits signés affichent un badge **Vérifié** ou **Non vérifié**.

   ![Liste de commits avec des badges vérifiée et non vérifiée.](img/project_signed_and_unsigned_commits_v17_4.png)

   Les commits non signés n'affichent aucun badge.

1. Pour afficher les détails de la signature d'un commit, sélectionnez **Vérifié** ou **Non vérifié** pour voir l'empreinte ou l'identifiant de clé :

   ![Détails de signature vérifiée pour un commit.](img/project_signed_commit_verified_signature_v17_4.png)

   ![Détails de signature non vérifiée pour un commit.](img/project_signed_commit_unverified_signature_v17_4.png)

Vous pouvez également [utiliser l'API commits](../../../../api/commits.md#retrieve-commit-signature) pour vérifier la signature d'un commit.

### Vérifier les commits signés par GitLab {#verify-gitlab-signed-commits}

GitLab signe les commits qu'il crée, comme les commits effectués via l'interface web, avec une clé configurée sur l'instance. Pour vérifier ces commits localement, obtenez la clé publique GitLab pour la signature des commits à l'aide de l'[API des commits web](../../../../api/web_commits.md#retrieve-public-signing-key).

La signature reste associée au commit lorsque celui-ci est copié dans un autre projet, par exemple via la [mise en miroir du dépôt](../mirror/_index.md). Dans le projet cible, GitLab affiche le badge **Vérifié** uniquement si l'instance est configurée avec la clé qui a signé le commit.

### Badge d'avertissement pour l'adresse e-mail du validateur non vérifiée {#warning-badge-for-unverified-committer-email}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/425042) dans GitLab 17.5 [avec le feature flag](../../../../administration/feature_flags/_index.md) `check_for_mailmapped_commit_emails`. Fonctionnalité désactivée par défaut.
- [Activé sur GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/work_items/481441) dans GitLab 18.9.
- [Passage en disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/issues/481441) dans GitLab 19.1. Le feature flag `check_for_mailmapped_commit_emails` a été supprimé.

{{< /history >}}

Lorsque l'adresse e-mail du validateur d'un commit signé vérifié n'est plus vérifiée pour l'utilisateur signataire, GitLab affiche un badge de vérification orange avec un signe d'avertissement ({{< icon name="warning" >}} **Vérifié**).

Cela peut se produire lorsque l'adresse e-mail du validateur a été supprimée des adresses e-mail vérifiées de l'utilisateur.

Pour restaurer le badge vert **Vérifié**, ajoutez l'adresse e-mail du validateur à votre profil GitLab et vérifiez-la.

## Imposer des commits signés avec des règles push {#enforce-signed-commits-with-push-rules}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez exiger des commits signés dans vos projets à l'aide de règles push. La règle push **Rejeter les validations sans signature** empêche tout commit non signé d'être poussé vers un dépôt, aidant ainsi les organisations à maintenir l'intégrité du code et à respecter les exigences de conformité.

Pour plus d'informations sur le fonctionnement de cette règle et ses limitations, consultez [exiger des commits signés](../push_rules.md#require-signed-commits).

## Dépannage {#troubleshooting}

### Résoudre les problèmes de vérification liés aux commits signés {#fix-verification-problems-with-signed-commits}

Le processus de vérification des commits signés avec des clés GPG ou des certificats X.509 peut échouer pour plusieurs raisons :

| Valeur                       | Description | Corrections possibles |
|-----------------------------|-------------|----------------|
| `UNVERIFIED`                | La signature du commit n'est pas valide. | Signez le commit avec une signature valide. |
| `SAME_USER_DIFFERENT_EMAIL` | La clé GPG utilisée pour signer le commit ne contient pas l'adresse e-mail du validateur, mais contient une autre adresse e-mail valide pour ce validateur. | Modifiez le commit pour utiliser une adresse e-mail correspondant à la clé GPG, ou mettez à jour la clé GPG [pour inclure l'adresse e-mail](https://security.stackexchange.com/a/261468). |
| `OTHER_USER`                | La signature et la clé GPG sont valides, mais la clé appartient à un utilisateur différent du validateur. | Modifiez le commit pour utiliser l'adresse e-mail correcte, ou modifiez le commit pour utiliser une clé GPG associée à votre utilisateur. |
| `UNVERIFIED_KEY`            | La clé associée à la signature GPG ne possède aucune adresse e-mail vérifiée associée au validateur. | Ajoutez et vérifiez l'adresse e-mail dans votre profil GitLab, [mettez à jour la clé GPG pour inclure l'adresse e-mail](https://security.stackexchange.com/a/261468), ou modifiez le commit pour utiliser une adresse e-mail de validateur différente. |
| `UNKNOWN_KEY`               | La clé GPG associée à la signature GPG de ce commit est inconnue de GitLab. | [Ajoutez la clé GPG](gpg.md#add-a-gpg-key-to-your-account) à votre profil GitLab. |
| `MULTIPLE_SIGNATURES`       | Plusieurs signatures GPG ou X.509 ont été trouvées pour le commit. | Modifiez le commit pour n'utiliser qu'une seule signature GPG ou X.509. |
