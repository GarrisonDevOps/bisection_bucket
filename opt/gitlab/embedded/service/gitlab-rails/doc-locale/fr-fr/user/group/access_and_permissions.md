---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Configurer et gérer l'accès et les autorisations des groupes."
title: Accès et autorisations des groupes
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Configurez vos groupes pour contrôler les autorisations et l'accès des groupes. Pour plus d'informations, consultez également [Partager des projets et des groupes](../project/members/sharing_projects_groups.md).

## Restreindre les protocoles d'accès Git {#restrict-git-access-protocols}

Vous pouvez définir les protocoles autorisés pour accéder aux dépôts d'un groupe : SSH, HTTPS, ou les deux. Ce paramètre est désactivé lorsque le [paramètre d'instance](../../administration/settings/visibility_and_access_controls.md#configure-enabled-git-access-protocols) est configuré par un administrateur.

Pour modifier les protocoles d'accès Git autorisés pour un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Permissions et fonctionnalités du groupe**.
1. Choisissez les protocoles autorisés dans **Protocoles d'accès Git activés**.
1. Sélectionnez **Enregistrer les modifications**.

## Restreindre l'accès au groupe par adresse IP {#restrict-group-access-by-ip-address}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Pour vous assurer que seules les personnes de votre organisation peuvent accéder à des ressources spécifiques, vous pouvez restreindre l'accès aux groupes par adresse IP. Ce paramètre de groupe principal s'applique à :

- L'interface utilisateur GitLab, y compris les sous-groupes, les projets et les tickets. Il ne s'applique pas à GitLab Pages.
- L'API.
- Sur GitLab Self-Managed, vous pouvez également configurer des [plages d'adresses IP autorisées globalement](../../administration/settings/visibility_and_access_controls.md#configure-globally-allowed-ip-address-ranges) pour le groupe.

Les administrateurs peuvent combiner la restriction d'accès par adresse IP avec les [adresses IP autorisées globalement](../../administration/settings/visibility_and_access_controls.md#configure-globally-allowed-ip-address-ranges).

> [!warning]
> La restriction par IP nécessite une configuration correcte de l'en-tête `X-Forwarded-For`. Pour limiter le risque d'usurpation d'adresse IP, vous devez écraser, et non ajouter, les en-têtes `X-Forwarded-For` envoyés par les clients.
>
> Pour les déploiements sans proxy en amont ni équilibreur de charge, configurez le serveur qui reçoit les requêtes directes des utilisateurs pour préserver l'adresse IP du client d'origine et écraser tous les en-têtes `X-Forwarded-For`. Dans NGINX, par exemple, modifiez votre fichier de configuration pour inclure :
>
> ```plaintext
> proxy_set_header X-Forwarded-For $remote_addr;
> ```
>
> Pour les déploiements avec un proxy en amont ou un équilibreur de charge, configurez le proxy ou l'équilibreur de charge pour préserver l'adresse IP du client d'origine et écraser tous les en-têtes `X-Forwarded-For`. Cette approche garantit que GitLab reçoit la chaîne complète des adresses IP, en commençant par le client d'origine, et peut évaluer correctement les restrictions IP. Dans NGINX, par exemple, modifiez votre fichier de configuration pour inclure :
>
> ```plaintext
> proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
> ```

Pour restreindre l'accès au groupe par adresse IP :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Permissions et fonctionnalités du groupe**.
1. Dans la zone de texte **Restreindre l'accès selon l'adresse IP**, saisissez une liste de plages d'adresses IPv4 ou IPv6 en notation CIDR :

   ```txt
   192.168.1.0/24
   10.0.0.0/8
   2001:db8::/32
   203.0.113.5/32
   ```

   Vous devez ajouter manuellement chaque entrée d'adresse IP. L'ajout de plusieurs entrées séparées par une virgule ou un espace n'est pas pris en charge. La prise en charge des entrées en masse est proposée dans le [ticket 468998](https://gitlab.com/gitlab-org/gitlab/-/work_items/468998).

   Cette liste :
   - N'a pas de limite sur le nombre de plages d'adresses IP.
   - S'applique aux plages d'adresses IP autorisées pour SSH ou HTTP. Vous ne pouvez pas diviser cette liste par type d'autorisation.
1. Sélectionnez **Enregistrer les modifications**.

### Implications pour la sécurité {#security-implications}

Les restrictions d'accès par IP limitent l'accès aux groupes et aux projets, mais ne constituent pas un pare-feu complet. Bien que cette fonctionnalité limite généralement l'accès aux ressources des groupes et des projets, certaines informations peuvent rester accessibles aux utilisateurs restreints. Gardez à l'esprit la liste suivante (non exhaustive) des implications pour la sécurité lors de l'accès à GitLab depuis une adresse IP non autorisée :

- Les administrateurs et les Owners de groupe peuvent toujours accéder aux paramètres du groupe.
- Les administrateurs peuvent toujours accéder aux projets du groupe. Cela inclut le clonage du code.
- Les Owners de groupe peuvent toujours accéder aux sous-groupes, mais pas aux projets du groupe ou des sous-groupes.
- Les utilisateurs peuvent toujours accéder aux ressources partagées.
- Les utilisateurs peuvent toujours consulter les noms et les hiérarchies des groupes et des projets.
- Les utilisateurs peuvent toujours utiliser la [fonctionnalité de réponse par e-mail](../../administration/reply_by_email.md) pour créer et modifier des commentaires sur des tickets ou des merge requests.
- Les utilisateurs peuvent créer des tickets et des merge requests par e-mail grâce à leur [jeton d'e-mail entrant](../../security/tokens/_index.md#incoming-email-token), car les e-mails entrants ne sont pas soumis aux restrictions IP.
- Les utilisateurs peuvent parfois consulter les événements de push, de merge, de ticket ou de commentaire sur leur tableau de bord.
- Les restrictions IP s'appliquent toujours aux projets publics, mais les fichiers de projet mis en cache peuvent parfois être accessibles.
- Les restrictions IP s'appliquent toujours aux opérations Git via SSH sur GitLab.com et GitLab Dedicated. Les instances GitLab Self-Managed doivent utiliser `gitlab-sshd` avec le [protocole PROXY](../../administration/operations/gitlab_sshd.md#proxy-protocol-support) activé.
- Les restrictions IP s'appliquent toujours aux opérations de clonage Git effectuées par les jobs CI/CD.
- Les restrictions IP ne s'appliquent pas à l'enregistrement des runners ni lorsque les runners demandent ou mettent à jour des jobs CI/CD.
- Les restrictions IP peuvent ne pas s'appliquer aux projets dupliqués ou aux actions qui interagissent indirectement avec des tickets ou des artefacts dans un groupe soumis à des restrictions IP. Par exemple, une merge request qui clôt un ticket dans un groupe soumis à des restrictions IP en utilisant une référence de ticket dans la description de la merge request.
- Les restrictions IP s'appliquent aux jetons d'accès aux projets et aux groupes, aux comptes de service, aux clés de déploiement et aux jetons de déploiement.

### Restrictions d'accès sur GitLab.com {#gitlabcom-access-restrictions}

La restriction d'accès aux groupes basée sur l'adresse IP ne fonctionne pas avec les [runners hébergés pour GitLab.com](../../ci/runners/hosted_runners/_index.md). Ces runners fonctionnent comme des machines virtuelles éphémères avec des [adresses IP dynamiques](../gitlab_com/_index.md#ip-range) provenant de grands pools de fournisseurs cloud (AWS, Google Cloud). Autoriser ces larges plages d'adresses IP va à l'encontre de l'objectif de la restriction d'accès basée sur l'adresse IP.

## Restreindre l'accès au groupe par domaine {#restrict-group-access-by-domain}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Vous pouvez définir une liste d'autorisation de domaines d'e-mail au niveau de l'espace de nommage principal pour restreindre les utilisateurs pouvant accéder à un groupe et à ses projets. Le domaine d'e-mail principal d'un utilisateur doit correspondre à une entrée de la liste d'autorisation pour accéder à ce groupe. Les sous-groupes héritent de la même liste d'autorisation.

Pour restreindre l'accès au groupe par domaine :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Permissions et fonctionnalités du groupe**.
1. Dans la zone de texte **Restreindre l'adhésion par domaine de messagerie**, saisissez les noms de domaine à autoriser.
1. Sélectionnez **Enregistrer les modifications**.

La prochaine fois que vous tenterez d'ajouter un utilisateur au groupe, son [e-mail principal](../profile/_index.md#change-your-primary-email) devra correspondre à l'un des domaines autorisés.

Vous ne pouvez pas restreindre l'utilisation des domaines d'e-mail publics les plus populaires, tels que :

- `aol.com`, `gmail.com`, `hotmail.co.uk`, `hotmail.com`,
- `hotmail.fr`, `icloud.com`, `live.com`, `mail.com`,
- `me.com`, `msn.com`, `outlook.com`,
- `proton.me`, `protonmail.com`, `tutanota.com`,
- `yahoo.com`, `yandex.com`, `zohomail.com`

Lorsque vous partagez un groupe, les espaces de nommage source et cible doivent tous deux autoriser les domaines des adresses e-mail des membres.

> [!note]
> La suppression d'un domaine de la liste **Restreindre l'adhésion par domaine de messagerie** ne supprime pas les utilisateurs existants ayant ce domaine du groupe ou de ses projets. De plus, si vous partagez un groupe ou un projet avec un autre groupe, le groupe cible peut ajouter davantage de domaines d'e-mail à sa liste qui ne figurent pas dans la liste du groupe source. Par conséquent, cette fonctionnalité ne garantit pas que les membres actuels respectent toujours la liste **Restreindre l'adhésion par domaine de messagerie**.

## Empêcher les utilisateurs de demander l'accès à un groupe {#prevent-users-from-requesting-access-to-a-group}

En tant qu'Owner de groupe, vous pouvez empêcher les non-membres de demander l'accès à votre groupe.

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Permissions et fonctionnalités du groupe**.
1. Décochez la case **Autoriser les utilisateurs à demander l'accès**.
1. Sélectionnez **Enregistrer les modifications**.

> [!note]
> La désactivation du paramètre **Autoriser les utilisateurs à demander l'accès** empêche les nouvelles demandes d'accès. Les demandes en attente existantes ne sont pas supprimées et peuvent toujours être approuvées ou refusées.

## Empêcher la duplication de projet en dehors du groupe {#prevent-project-forking-outside-group}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Par défaut, les projets d'un groupe peuvent être dupliqués. Cependant, vous pouvez empêcher les projets d'un groupe d'être dupliqués en dehors du groupe principal actuel.

> [!note]
> Empêchez la duplication en dehors du groupe principal dans la mesure du possible pour réduire les risques liés à des acteurs malveillants. Cependant, si vous prévoyez beaucoup de collaboration externe, autoriser les duplications en dehors du groupe principal peut s'avérer inévitable.

Prérequis :

- Ce paramètre est activé uniquement sur le groupe principal.
- Tous les sous-groupes héritent de ce paramètre du groupe principal, et il ne peut pas être modifié au niveau du sous-groupe.

Pour empêcher la duplication de projets en dehors du groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Permissions et fonctionnalités du groupe**.
1. Cochez **Empêcher la duplication du projet en dehors du groupe actuel**.
1. Sélectionnez **Enregistrer les modifications**.

Les duplications existantes ne sont pas supprimées.

## Empêcher l'ajout de membres aux projets d'un groupe {#prevent-members-from-being-added-to-projects-in-a-group}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

En tant qu'Owner de groupe, vous pouvez empêcher tout nouveau membre dans l'ensemble des projets d'un groupe, ce qui permet un contrôle plus strict des membres du projet.

Par exemple, si vous souhaitez verrouiller le groupe pour un [événement d'audit](../../administration/compliance/audit_event_reports.md), vous pouvez garantir que les membres du projet ne peuvent pas être modifiés pendant l'audit.

Si le verrouillage des membres du groupe est activé, l'Owner du groupe peut toujours :

- Inviter des groupes ou ajouter des membres à des groupes pour leur donner accès aux projets du groupe **verrouillé**.
- Modifier le rôle des membres du groupe.

Le paramètre n'est pas propagé en cascade. Les projets des sous-groupes respectent la configuration du sous-groupe, en ignorant le groupe parent.

Pour empêcher l'ajout de membres aux projets d'un groupe :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez la section **Permissions et fonctionnalités du groupe**.
1. Sous **Appartenance**, sélectionnez **Les utilisateurs ne peuvent pas être ajoutés aux projets de ce groupe**.
1. Sélectionnez **Enregistrer les modifications**.

Après avoir verrouillé les membres d'un groupe :

- Tous les utilisateurs qui avaient précédemment des autorisations ne peuvent plus ajouter de membres à un groupe.
- Les requêtes API pour ajouter un nouvel utilisateur à un projet ne sont pas possibles.

## Gérer les membres du groupe avec LDAP {#manage-group-memberships-with-ldap}

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed

{{< /details >}}

{{< history >}}

- La prise en charge des rôles personnalisés pour les utilisateurs synchronisés dans les groupes a été [introduite](https://gitlab.com/gitlab-org/gitlab/-/issues/435229) dans GitLab 17.2.

{{< /history >}}

La synchronisation de groupe permet de mapper des groupes LDAP vers des groupes GitLab. Cela offre un meilleur contrôle sur la gestion des utilisateurs par groupe. Pour configurer la synchronisation de groupe, modifiez le `group_base` **DN** (`'OU=Global Groups,OU=GitLab INT,DC=GitLab,DC=org'`). Cette **OU** contient tous les groupes associés aux groupes GitLab.

Les liens de groupe peuvent être créés en utilisant soit un CN, soit un filtre. Pour créer ces liens de groupe, accédez à la page **Paramètres** > **Synchronisation LDAP** du groupe. Après avoir configuré le lien, il peut s'écouler plus d'une heure avant que les utilisateurs ne soient synchronisés avec le groupe GitLab. Après avoir configuré le lien :

Les Owners de groupe peuvent utiliser l'[API des rôles de membre](../../api/member_roles.md) ou l'[API des membres de groupe](../../api/group_members.md#add-a-group-member) pour ajouter ou supprimer un compte de service du groupe, même lorsque la synchronisation LDAP est activée pour le groupe. Les Owners de groupe ne peuvent pas ajouter ou supprimer des utilisateurs qui ne sont pas des comptes de service.

Lorsqu'un utilisateur appartient à plusieurs groupes LDAP configurés pour le même groupe GitLab, GitLab lui attribue le plus élevé des deux rôles associés. Par exemple :

- L'utilisateur est membre des groupes LDAP `Owner` et `Dev`.
- Le groupe GitLab est configuré avec ces deux groupes LDAP.
- Lorsque la synchronisation de groupe est terminée, l'utilisateur se voit attribuer le rôle `Owner`, car c'est le plus élevé des deux rôles de groupe LDAP.

Avec les rôles personnalisés, la même logique s'applique lorsque les rôles ont des niveaux d'accès de base différents. Par exemple :

- Si l'utilisateur est membre des groupes LDAP `Developer` et `Developer + admin_vulnerability`
- L'utilisateur se voit attribuer `Developer + admin_vulnerability`, car c'est le plus élevé des deux rôles de groupe LDAP.

Lorsque deux rôles personnalisés partagent le même niveau d'accès de base, GitLab ne peut pas déterminer un rôle plus élevé par rang seul. À la place, le rôle personnalisé du lien de groupe créé le plus tôt est prioritaire. Par exemple :

- Si un utilisateur est membre des groupes LDAP `Developer + admin_vulnerability` et `Developer + admin_merge_request`
- Les deux rôles partagent le niveau d'accès de base `Developer`.
- L'utilisateur se voit attribuer le lien de groupe LDAP créé le plus tôt.

Pour plus d'informations sur l'administration de LDAP et la synchronisation de groupe, consultez la [documentation principale LDAP](../../administration/auth/ldap/ldap_synchronization.md#group-sync).

> [!note]
> Lorsque vous ajoutez la synchronisation de groupe LDAP, si un utilisateur LDAP est membre du groupe et n'appartient pas au groupe LDAP, il est supprimé du groupe.

Vous pouvez utiliser une solution de contournement pour [gérer l'accès aux projets via des groupes LDAP](../project/working_with_projects.md#manage-project-access-through-ldap-groups).

### Créer des liens de groupe avec un CN {#create-group-links-with-a-cn}

Pour créer des liens de groupe avec le CN du groupe LDAP :

<!-- vale gitlab_base.Spelling = NO -->

1. Sélectionnez le **serveur LDAP** pour le lien.
1. Comme **Méthode de synchronisation**, sélectionnez `LDAP Group cn`.
1. Dans le champ **CN du groupe LDAP**, commencez à saisir le CN du groupe. Une liste déroulante s'affiche avec les CN correspondants dans le `group_base` configuré. Sélectionnez votre CN dans cette liste.
1. Dans la section **Accès LDAP**, choisissez un [rôle par défaut](../permissions.md) ou un [rôle de membre personnalisé](../custom_roles/_index.md) pour les utilisateurs synchronisés dans ce groupe.
1. Sélectionnez **Ajouter une synchronisation**.

GitLab commence à lier le rôle à tous les utilisateurs LDAP correspondants. Ce processus peut prendre plus d'une heure.

<!-- vale gitlab_base.Spelling = YES -->

### Créer des liens de groupe avec un filtre {#create-group-links-with-a-filter}

Pour créer des liens de groupe avec un filtre d'utilisateurs LDAP :

1. Sélectionnez le **serveur LDAP** pour le lien.
1. Comme **Méthode de synchronisation**, sélectionnez `LDAP user filter`.
1. Saisissez votre filtre dans la zone **Filtre d'utilisateurs LDAP**. Suivez la [documentation sur les filtres d'utilisateurs](../../administration/auth/ldap/_index.md#set-up-ldap-user-filter).
1. Dans la section **Accès LDAP**, choisissez un [rôle par défaut](../permissions.md) ou un [rôle de membre personnalisé](../custom_roles/_index.md) pour les utilisateurs synchronisés dans ce groupe.
1. Sélectionnez **Ajouter une synchronisation**.

GitLab commence à lier le rôle à tous les utilisateurs LDAP correspondants. Ce processus peut prendre plus d'une heure.

### Supprimer des liens de groupe {#remove-group-links}

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Synchronisation active**.
1. Identifiez le lien de groupe que vous souhaitez supprimer et sélectionnez **Supprimer**.

> [!note]
> Lorsque vous supprimez la synchronisation de groupe LDAP, les membres existants et les attributions de rôles sont conservés. Si le groupe ne comporte plus de liens de groupe LDAP, vous pouvez modifier ces membres directement. Vous n'avez pas besoin de les remplacer au préalable.

### Remplacer les autorisations des utilisateurs {#override-user-permissions}

Les autorisations des utilisateurs LDAP peuvent être remplacées manuellement par un administrateur. Pour remplacer les autorisations d'un utilisateur :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Gérer** > **Membres**. Si la synchronisation LDAP a accordé à un utilisateur un rôle avec :
   - Plus d'autorisations que le membre du groupe parent, cet utilisateur apparaît comme ayant un [membre direct](../project/members/_index.md#display-direct-members) du groupe.
   - Le même nombre ou moins d'autorisations que le membre du groupe parent, cet utilisateur apparaît comme ayant un [membre hérité](../project/members/_index.md#membership-types) du groupe.
1. Facultatif. Si l'utilisateur que vous souhaitez modifier apparaît comme ayant un membre hérité, [filtrez le sous-groupe pour afficher les membres directs](_index.md#filter-a-group) avant de remplacer les autorisations de l'utilisateur LDAP.
1. Dans la ligne de l'utilisateur que vous modifiez, sélectionnez l'icône en forme de crayon ({{< icon name="pencil" >}}).
1. Sélectionnez **Modifier les autorisations** dans la boîte de dialogue.

Vous pouvez maintenant modifier les autorisations de l'utilisateur depuis la page **Membres**.

## Définir le rôle par défaut pouvant utiliser les variables de pipeline {#set-the-default-role-that-can-use-pipeline-variables}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/issues/513117) dans GitLab 17.10.

{{< /history >}}

Ce paramètre de groupe contrôle la valeur par défaut du paramètre de projet [rôle minimum autorisé à exécuter un nouveau pipeline avec des variables de pipeline](../../ci/variables/_index.md#restrict-pipeline-variables). Les nouveaux projets créés dans le groupe ont cette valeur sélectionnée par défaut.

Prérequis :

- Vous devez disposer du rôle Maintainer ou Owner dans le groupe.
- Le groupe doit être le groupe principal, et non un sous-groupe.

Pour définir le rôle minimum par défaut :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **CI/CD** > **Variables**.
1. Sous **Rôle autorisé par défaut à utiliser les variables de pipeline**, sélectionnez un rôle minimum ou sélectionnez **Aucun rôle autorisé** pour empêcher tout utilisateur d'utiliser des variables de pipeline.
1. Sélectionnez **Enregistrer les modifications**.

Après la création d'un nouveau projet, les membres du projet disposant du rôle Maintainer ou Owner peuvent modifier le paramètre du projet en une autre valeur si nécessaire.

## Autoriser l'accès au serveur MCP {#allow-access-to-the-mcp-server}

{{< details >}}

- Offre : GitLab.com

{{< /details >}}

{{< history >}}

- [Introduction](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230311) dans GitLab 19.0 [avec le feature flag](../../administration/feature_flags/_index.md) `mcp_server_availability_setting`. Fonctionnalité désactivée par défaut.
- [Disponibilité générale](https://gitlab.com/gitlab-org/gitlab/-/work_items/598279) dans GitLab 19.2. Le feature flag `mcp_server_availability_setting` a été supprimé.
- [Activé](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/241093) dans GitLab 19.2 pour les groupes principaux existants avec les fonctionnalités GitLab Duo et les fonctionnalités expérimentales et en version bêta activées.
- [Activé par défaut](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/256761) pour les groupes principaux créés dans GitLab 19.5 et versions ultérieures.

{{< /history >}}

L'état de ce paramètre pour votre groupe dépend de la date de création du groupe :

- Groupes existant au moment de l'ajout du paramètre : activé uniquement si le groupe avait à la fois les fonctionnalités GitLab Duo et les fonctionnalités expérimentales et en version bêta activées à ce moment-là.
- Groupes créés après cette date, jusqu'à GitLab 19.5 : désactivé par défaut.
- Groupes créés dans GitLab 19.5 et versions ultérieures : activé par défaut.

Un Owner peut activer ou désactiver le paramètre pour tout groupe principal.

Prérequis :

- Disposer du rôle Propriétaire pour le groupe principal.

Pour modifier l'accès au serveur MCP pour un groupe principal :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre groupe principal.
1. Dans la barre latérale gauche, sélectionnez **Paramètres** > **Généralités**.
1. Développez **Permissions et fonctionnalités du groupe**.
1. Dans la section **Accès au client MCP**, cochez ou décochez la case **Autoriser la connexion à GitLab**.
1. Sélectionnez **Enregistrer les modifications**.

## Dépannage {#troubleshooting}

### Vérifier si l'accès est bloqué par une restriction IP {#verify-if-access-is-blocked-by-ip-restriction}

Si un utilisateur voit une erreur 404 lorsqu'il tente d'accéder à un groupe spécifique, son accès peut être bloqué par une restriction IP.

Recherchez dans le journal Rails `auth.log` une ou plusieurs des entrées suivantes :

- `json.message` : `'Attempting to access IP restricted group'`
- `json.allowed` : `false`

En consultant les entrées du journal, comparez `remote.ip` avec la liste des [adresses IP autorisées](#restrict-group-access-by-ip-address) pour le groupe.

### Impossible de mettre à jour les autorisations d'un membre du groupe {#cannot-update-permissions-for-a-group-member}

Si un Owner de groupe ne peut pas mettre à jour les autorisations d'un membre du groupe, vérifiez quels membres sont répertoriés. Les Owners de groupe ne peuvent mettre à jour que les membres directs.

Les membres ajoutés directement à un sous-groupe sont toujours considérés comme des [membres hérités](../project/members/_index.md#membership-types) s'ils ont le même rôle ou un rôle supérieur dans le groupe parent.

Pour consulter et mettre à jour les membres directs, [filtrez le groupe pour afficher les membres directs](_index.md#filter-a-group).

Le [ticket 337539](https://gitlab.com/gitlab-org/gitlab/-/issues/337539#note_1277786161) propose une page des membres repensée qui répertorie les membres directs et indirects avec la possibilité de filtrer par type.

### Impossible de cloner ou de tirer (pull) via SSH après avoir activé les restrictions IP {#cannot-clone-or-pull-using-ssh-after-enabling-ip-restrictions}

Si vous rencontrez des problèmes avec les opérations Git SSH après avoir ajouté des restrictions d'adresse IP, vérifiez si votre connexion utilise IPv6 par défaut.

Certains systèmes d'exploitation donnent la priorité à IPv6 sur IPv4 lorsque les deux sont disponibles, ce qui peut ne pas être évident à partir des retours du terminal Git.

Si votre connexion utilise IPv6, vous pouvez résoudre ce problème en ajoutant l'adresse IPv6 à la liste d'autorisation.
