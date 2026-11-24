---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Clés de déploiement
description: "Clés SSH publiques, accès aux dépôts, utilisateurs bots et accès en lecture seule."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Utilisez des clés de déploiement pour accéder aux dépôts hébergés dans GitLab. Dans la plupart des cas, vous utilisez des clés de déploiement pour accéder à un dépôt depuis un hôte externe, comme un serveur de build ou un serveur d'intégration continue (CI).

Selon vos besoins, vous pouvez utiliser un [jeton de déploiement](../deploy_tokens/_index.md) pour accéder à un dépôt à la place.

| Attribut        |  Clé de déploiement | Jeton de déploiement |
|------------------|-------------|--------------|
| Partage          | Peut être partagée entre plusieurs projets, même ceux appartenant à des groupes différents. | Appartient à un projet ou à un groupe. |
| Source           | Clé SSH publique générée sur un hôte externe. | Générée sur votre instance GitLab et fournie aux utilisateurs uniquement au moment de la création. |
| Ressources accessibles  | Dépôt Git via SSH | Dépôt Git via HTTP, registre de paquets et registre de conteneurs. |

Les clés de déploiement ne peuvent pas être utilisées pour les opérations Git si [l'autorisation externe](../../../administration/settings/external_authorization.md) est activée.

## Portée {#scope}

Une clé de déploiement possède une portée définie lors de sa création :

- **Clé de déploiement de projet** : l'accès est limité au projet sélectionné.
- **Clé de déploiement publique** : l'accès peut être accordé à n'importe quel projet d'une instance GitLab. L'accès à chaque projet doit être [accordé](#grant-project-access-to-a-public-deploy-key) par un utilisateur disposant au minimum du rôle Maintainer.

Vous ne pouvez pas modifier la portée d'une clé de déploiement après sa création.

## Autorisations {#permissions}

Une clé de déploiement se voit attribuer un niveau d'autorisation lors de sa création :

- **Lecture seule** : une clé de déploiement en lecture seule ne peut que lire depuis le dépôt.
- **Lecture-écriture** : une clé de déploiement en lecture-écriture peut lire depuis le dépôt et y écrire.

Vous pouvez modifier le niveau d'autorisation d'une clé de déploiement après sa création. La modification des autorisations d'une clé de déploiement de projet s'applique uniquement au projet en cours.

Si un push utilisant une clé de déploiement déclenche des processus supplémentaires, le créateur de la clé doit être autorisé. Par exemple :

- Lorsqu'une clé de déploiement est utilisée pour pousser un commit vers une [branche protégée](../repository/branches/protected.md), le créateur de la clé de déploiement doit avoir accès à la branche.
- Lorsqu'une clé de déploiement est utilisée pour pousser un commit qui déclenche un pipeline CI/CD, le créateur de la clé de déploiement doit avoir accès aux ressources CI/CD, y compris les environnements protégés et les variables secrètes.

### Implications pour la sécurité {#security-implications}

Les clés de déploiement sont destinées à faciliter les interactions non humaines avec GitLab. Par exemple, vous pouvez utiliser une clé de déploiement pour accorder des autorisations à un script qui s'exécute automatiquement sur un serveur de votre organisation.

Vous devez utiliser [un compte de service](../../profile/service_accounts.md) et créer la clé de déploiement avec ce compte de service. Si vous utilisez un autre compte utilisateur pour créer des clés de déploiement, cet utilisateur se voit accorder des privilèges qui persistent jusqu'à la révocation de la clé de déploiement.

De plus :

- Si le propriétaire de la clé de déploiement est bloqué, la clé de déploiement est [rejetée](#deploy-key-is-rejected). Elle ne peut être utilisée pour aucune opération sur le dépôt, y compris les pulls et les pushes.
- Les clés de déploiement ne sont pas rejetées lorsque le propriétaire de la clé de déploiement est retiré du groupe ou du projet. La clé de déploiement continue de fournir un accès jusqu'à ce qu'elle soit révoquée.
- Lorsqu'une clé de déploiement est spécifiée dans une règle de branche protégée, le créateur de la clé de déploiement :
  - Obtient l'accès à la branche protégée et à la clé de déploiement elle-même.
  - Peut pousser vers la branche protégée si la clé de déploiement possède l'autorisation de lecture-écriture. Cela est vrai même si la branche est protégée contre les modifications de tous les utilisateurs.

Comme pour toute information sensible, vous devez vous assurer que seules les personnes ayant besoin d'accéder au secret peuvent le lire. Pour les interactions humaines, utilisez des identifiants liés aux utilisateurs, tels que les jetons d'accès personnels.

Pour détecter une fuite potentielle de secret, vous pouvez utiliser la fonctionnalité [d'événement d'audit](../../compliance/audit_event_schema.md#example-audit-event-payloads-for-git-over-ssh-events-with-deploy-key).

## Afficher les clés de déploiement {#view-deploy-keys}

Pour afficher les clés de déploiement disponibles pour un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Clés de déploiement**.

Les clés de déploiement disponibles sont répertoriées :

- **Clés de déploiement activées** : clés de déploiement qui ont accès au projet.
- **Clés de déploiement à accès privé** : clés de déploiement de projet qui n'ont pas accès au projet.
- **Clés de déploiement à accès public** : clés de déploiement publiques qui n'ont pas accès au projet.

L'[interface de ligne de commande GitLab](../../../editor_extensions/gitlab_cli/_index.md) fournit une commande `glab deploy-key list`.

## Créer une clé de déploiement de projet {#create-a-project-deploy-key}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.
- [Générez une paire de clés SSH](../../ssh.md#generate-an-ssh-key-pair). Placez la clé SSH privée sur l'hôte qui nécessite l'accès au dépôt.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Clés de déploiement**.
1. Sélectionnez **Ajouter une nouvelle clé**.
1. Remplissez les champs.
1. Facultatif. Pour accorder l'autorisation `read-write`, cochez la case **Accorder des autorisations d'écriture à cette clé**.
1. Facultatif. Mettez à jour la **Date d'expiration**.

Une clé de déploiement de projet est activée lors de sa création. Vous pouvez uniquement modifier le nom et les autorisations d'une clé de déploiement de projet. Si la clé de déploiement est activée dans plusieurs projets, vous ne pouvez pas modifier le nom de la clé de déploiement.

L'[interface de ligne de commande GitLab](../../../editor_extensions/gitlab_cli/_index.md) fournit une commande `glab deploy-key add`.

## Créer une clé de déploiement publique {#create-a-public-deploy-key}

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Prérequis :

- Vous devez disposer d'un accès administrateur à l'instance.
- Vous devez [générer une paire de clés SSH](../../ssh.md#generate-an-ssh-key-pair).
- Vous devez placer la clé SSH privée sur l'hôte qui nécessite l'accès au dépôt.

Pour créer une clé de déploiement publique :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **Accès** > **Clés de déploiement**.
1. Sélectionnez **Nouvelle clé de déploiement**.
1. Remplissez les champs.
   - Utilisez une description pertinente pour **Nom**. Par exemple, incluez le nom de l'hôte externe ou de l'application qui utilise la clé de déploiement publique.

Vous pouvez uniquement modifier le nom d'une clé de déploiement publique.

## Accorder l'accès au projet à une clé de déploiement publique {#grant-project-access-to-a-public-deploy-key}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour accorder à une clé de déploiement publique l'accès à un projet :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Clés de déploiement**.
1. Sélectionnez **Clés de déploiement à accès public**.
1. Dans la ligne de la clé, sélectionnez **Activer**.
1. Pour accorder l'autorisation de lecture-écriture à la clé de déploiement publique :
   1. Dans la ligne de la clé, sélectionnez **Modifier** ({{< icon name="pencil" >}}).
   1. Cochez la case **Accorder des autorisations d'écriture à cette clé**.

### Modifier les autorisations d'accès au projet d'une clé de déploiement {#edit-project-access-permissions-of-a-deploy-key}

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour modifier les autorisations d'accès au projet d'une clé de déploiement :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Clés de déploiement**.
1. Dans la ligne de la clé, sélectionnez **Modifier** ({{< icon name="pencil" >}}).
1. Cochez ou décochez la case **Accorder des autorisations d'écriture à cette clé**.

## Révoquer l'accès au projet d'une clé de déploiement {#revoke-project-access-of-a-deploy-key}

Pour révoquer l'accès d'une clé de déploiement à un projet, vous pouvez la désactiver. Tout service reposant sur une clé de déploiement cesse de fonctionner lorsque la clé est désactivée.

Prérequis :

- Vous devez disposer du rôle Chargé de maintenance ou Propriétaire dans le projet.

Pour désactiver une clé de déploiement :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Dépôt**.
1. Développez **Clés de déploiement**.
1. Sélectionnez **Désactiver** ({{< icon name="cancel" >}}).

Ce qui arrive à la clé de déploiement lorsqu'elle est désactivée dépend des éléments suivants :

- Si la clé est accessible publiquement, elle est retirée du projet mais reste disponible dans l'onglet **Clés de déploiement à accès public**.
- Si la clé est accessible de manière privée et utilisée uniquement par ce projet, elle est supprimée.
- Si la clé est accessible de manière privée et également utilisée par d'autres projets, elle est retirée du projet, mais reste disponible dans l'onglet **Clés de déploiement à accès privé**.

## Sujets connexes {#related-topics}

- Interface de ligne de commande GitLab — [commandes pour les clés de déploiement](https://gitlab.com/gitlab-org/cli/-/tree/main/docs/source/deploy-key)

## Dépannage {#troubleshooting}

### La clé de déploiement est rejetée {#deploy-key-is-rejected}

Une clé de déploiement est rejetée dans les cas suivants :

- Le propriétaire de la clé est bloqué.
- La clé a expiré.

Lorsqu'une clé de déploiement est rejetée, elle ne peut être utilisée pour aucune opération sur le dépôt, y compris les pulls et les pushes.

Pour résoudre ce problème :

- Si le propriétaire de la clé est bloqué, débloquez l'utilisateur ou [changez le propriétaire de la clé](#set-the-owner-of-a-deploy-key) pour un utilisateur actif.
- Si la clé a expiré, créez une nouvelle clé de déploiement.

### La clé de déploiement ne peut pas pousser vers une branche protégée {#deploy-key-cannot-push-to-a-protected-branch}

Il existe quelques scénarios dans lesquels une clé de déploiement échoue à pousser vers une [branche protégée](../repository/branches/protected.md).

- Le propriétaire associé à une clé de déploiement ne possède pas [l'appartenance](../members/_index.md) au projet de la branche protégée.
- Le propriétaire associé à une clé de déploiement possède des [autorisations d'appartenance au projet](../../permissions.md#project-permissions) inférieures à celles requises pour **Afficher le code du projet**.
- La clé de déploiement ne dispose pas des [autorisations de lecture-écriture pour le projet](#edit-project-access-permissions-of-a-deploy-key).
- La clé de déploiement a été [révoquée](#revoke-project-access-of-a-deploy-key).
- **Personne** n'est sélectionné dans [la section **Autorisés à pousser et fusionner**](../repository/branches/protected.md#protect-a-branch) de la branche protégée.

Ce problème survient parce que toutes les clés de déploiement sont associées à un compte. Étant donné que les autorisations d'un compte peuvent changer, cela peut entraîner des situations où une clé de déploiement qui fonctionnait devient soudainement incapable de pousser vers une branche protégée.

Pour résoudre ce problème, vous pouvez utiliser l'API des clés de déploiement pour créer des clés de déploiement pour les utilisateurs de comptes de service du projet, plutôt que pour vos propres utilisateurs :

1. [Créez un utilisateur de compte de service](../../../api/service_accounts.md#create-a-group-service-account).
1. [Créez un jeton d'accès personnel](../../../api/service_accounts.md#create-a-personal-access-token-for-a-group-service-account) pour cet utilisateur de compte de service. Ce jeton doit avoir au minimum la portée `api`.
1. [Invitez l'utilisateur de compte de service au projet](../../profile/service_accounts.md#add-a-service-account-to-a-group-or-project).
1. Utilisez l'API des clés de déploiement pour [créer une clé de déploiement pour l'utilisateur de compte de service](../../../api/deploy_keys.md#add-deploy-key) :

   ```shell
   curl --request POST --header "PRIVATE-TOKEN: <service_account_access_token>" \
     --header "Content-Type: application/json" \
     --data '{"title": "My deploy key", "key": "ssh-rsa AAAA...", "can_push": "true"}' \
     --url "https://gitlab.example.com/api/v4/projects/5/deploy_keys/"
   ```

#### Identifier les clés de déploiement associées aux utilisateurs non-membres et bloqués {#identify-deploy-keys-associated-with-non-member-and-blocked-users}

Si vous devez trouver les clés appartenant à un utilisateur non-membre ou bloqué, vous pouvez utiliser [la console Rails](../../../administration/operations/rails_console.md#starting-a-rails-console-session) pour identifier les clés de déploiement inutilisables à l'aide d'un script similaire au suivant :

```ruby
DeployKeysProject.with_write_access.find_each do |deploy_key_mapping|
  project = deploy_key_mapping.project
  deploy_key = deploy_key_mapping.deploy_key
  user = deploy_key.user

  access_checker = Gitlab::DeployKeyAccess.new(deploy_key, container: project)

  # can_push_for_ref? tests if deploy_key can push to default branch, which is likely to be protected
  can_push = access_checker.can_do_action?(:push_code)
  can_push_to_default = access_checker.can_push_for_ref?(project.repository.root_ref)

  next if access_checker.allowed? && can_push && can_push_to_default

  if user.nil? || user.ghost?
    username = 'none'
    state = '-'
  else
    username = user.username
    user_state = user.state
  end

  puts "Deploy key: #{deploy_key.id}, Project: #{project.full_path}, Can push?: " + (can_push ? 'YES' : 'NO') +
       ", Can push to default branch #{project.repository.root_ref}?: " + (can_push_to_default ? 'YES' : 'NO') +
       ", User: #{username}, User state: #{user_state}"
end
```

#### Définir le propriétaire d'une clé de déploiement {#set-the-owner-of-a-deploy-key}

Les clés de déploiement appartiennent à un utilisateur spécifique et sont rejetées lorsque l'utilisateur est bloqué. Pour qu'une clé de déploiement continue de fonctionner lorsque son propriétaire est bloqué, changez son propriétaire pour un utilisateur actif.

Si vous disposez de l'empreinte de la clé de déploiement, vous pouvez modifier l'utilisateur associé à une clé de déploiement à l'aide des commandes suivantes :

```shell
k = Key.find_by(fingerprint: '5e:51:92:11:27:90:01:b5:83:c3:87:e3:38:82:47:2e')
k.user_id = User.find_by(username: 'anactiveuser').id
k.save()
```
