---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Domaines personnalisés GitLab Pages
description: Configurer des domaines personnalisés et des certificats SSL/TLS pour un site GitLab Pages.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed

{{< /details >}}

Vous pouvez utiliser des domaines personnalisés :

- Avec GitLab Pages.
- Pour [contourner la confirmation par e-mail des utilisateurs provisionnés via SAML ou SCIM](../../../group/saml_sso/_index.md#bypass-user-email-confirmation-with-verified-domains). Lorsque vous utilisez des domaines personnalisés de cette manière, vous utilisez la fonctionnalité GitLab Pages mais pouvez ignorer les [prérequis](#prerequisites).

Pour utiliser un ou plusieurs noms de domaine personnalisés :

- Ajouter un [domaine racine ou sous-domaine personnalisé](#set-up-a-custom-domain).
- Ajouter une [certification SSL/TLS](#add-an-ssltls-certificate-to-pages).

> [!warning]
> Vous ne pouvez pas vérifier les [domaines de messagerie publics les plus courants](../../../group/access_and_permissions.md#restrict-group-access-by-domain).

## Configurer un domaine personnalisé {#set-up-a-custom-domain}

Pour configurer Pages avec un domaine personnalisé, suivez les étapes ci-dessous.

### Prérequis {#prerequisites}

- Un administrateur a configuré le serveur pour les [domaines personnalisés GitLab Pages](../../../../administration/pages/_index.md#configure-custom-domains).
- Un site GitLab Pages opérationnel, servi sous le domaine Pages par défaut (`*.gitlab.io`, pour GitLab.com).
- Un nom de domaine personnalisé `example.com` ou un sous-domaine `subdomain.example.com`.
- Accès au panneau de contrôle du serveur de votre domaine pour configurer les enregistrements DNS :
  - Un enregistrement DNS (`A`, `AAAA`, `ALIAS`, ou `CNAME`) pointant votre domaine vers le serveur GitLab Pages. S'il existe plusieurs enregistrements DNS pour ce nom, vous devez utiliser un enregistrement `ALIAS`.
  - Un enregistrement DNS `TXT` pour vérifier la propriété de votre domaine.

Pour une présentation des enregistrements DNS, consultez [Enregistrements DNS GitLab Pages](dns_concepts.md).

### Étape 1 :  ajouter un domaine personnalisé {#step-1-add-a-custom-domain}

Pour ajouter votre domaine personnalisé à GitLab Pages :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.
1. Dans le coin supérieur droit, sélectionnez **Nouveau domaine**.
1. Dans **Domaine**, saisissez le nom de domaine.
1. Facultatif. Dans **Certificat**, désactivez le bouton **Gestion automatique des certificats à l'aide de Let's Encrypt** pour ajouter un [certificat SSL/TLS](#add-an-ssltls-certificate-to-pages). Vous pouvez également ajouter le certificat et la clé ultérieurement.
1. Sélectionnez **Créer un nouveau domaine**.

### Étape 2 :  obtenir le code de vérification {#step-2-get-the-verification-code}

Après avoir ajouté un nouveau domaine à Pages, GitLab affiche un code de vérification. Copiez les valeurs et collez-les dans le panneau de contrôle de votre domaine en tant qu'enregistrement `TXT` à l'étape suivante.

![GitLab Pages affichant le code de vérification généré pour un nouveau domaine.](img/get_domain_verification_code_v18_8.png)

Le code de vérification a la structure suivante :

- Nom/Hôte :
  - Pour les domaines racines : `_gitlab-pages-verification-code.example.com`
  - Pour les sous-domaines : `_gitlab-pages-verification-code.subdomain.example.com`
- Type d'enregistrement DNS : `TXT`
- Valeur : `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` (utilisez votre code réel fourni par GitLab)

> [!note]
> Certains fournisseurs DNS, comme Cloudflare, ajoutent automatiquement votre nom de domaine au champ Nom ou Hôte. Si votre fournisseur fait cela, saisissez uniquement `_gitlab-pages-verification-code` pour les domaines racines ou `_gitlab-pages-verification-code.subdomain` pour les sous-domaines.

### Étape 3 :  configurer les enregistrements DNS {#step-3-set-up-dns-records}

Pour configurer les enregistrements DNS en fonction du type de domaine que vous souhaitez utiliser avec votre site Pages, choisissez l'une des options suivantes :

- [Domaines racines](#root-domains)
- [Sous-domaines](#subdomains)
- [Domaines racines et sous-domaines](#both-root-and-subdomains)

#### Domaines racines {#root-domains}

Les domaines racines (`example.com`) requièrent :

- Au moins l'un des éléments suivants :
  - Un [enregistrement DNS `A`](dns_concepts.md#a-record) pointant votre domaine vers le serveur Pages.
  - Un [enregistrement DNS `AAAA`](dns_concepts.md#aaaa-record) pointant votre domaine vers le serveur Pages.
- Un [enregistrement `TXT`](dns_concepts.md#txt-record) pour vérifier la propriété de votre domaine.

| De                                          | Enregistrement DNS | Vers              |
| --------------------------------------------- | ---------- | --------------- |
| `example.com`                                 | `A`        | `35.185.44.232` |
| `example.com`                                 | `AAAA`     | `2600:1901:0:7b8a::` |
| `_gitlab-pages-verification-code.example.com` | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |

Pour les projets sur GitLab.com, l'adresse IPv4 est `35.185.44.232` et l'adresse IPv6 est `2600:1901:0:7b8a::`.

Pour les projets sur d'autres instances GitLab (CE ou EE), contactez votre administrateur système et demandez l'adresse IP du serveur Pages pour votre instance.

![Écran de configuration DNS affichant un enregistrement A ajouté pour le serveur GitLab Pages.](img/dns_add_new_a_record_v11_2.png)

> [!warning]
> Vous ne devez pas utiliser un enregistrement DNS apex `CNAME` à la place d'un enregistrement `A` ou `AAAA` pour votre domaine racine. Cette méthode ne fonctionne très probablement pas si vous configurez un [enregistrement `MX`](dns_concepts.md#mx-record) pour votre domaine racine.

#### Sous-domaines {#subdomains}

Les sous-domaines (`subdomain.example.com`) requièrent :

- Un [enregistrement DNS `ALIAS` ou `CNAME`](dns_concepts.md#cname-record) pointant votre sous-domaine vers le serveur Pages.
- Un [enregistrement DNS `TXT`](dns_concepts.md#txt-record) pour vérifier la propriété de votre domaine.

| De                                                    | Enregistrement DNS      | Vers |
|---------------------------------------------------------|-----------------|----|
| `subdomain.example.com`                                 | `ALIAS`/`CNAME` | `namespace.gitlab.io` |
| `_gitlab-pages-verification-code.subdomain.example.com` | `TXT`           | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |

Qu'il s'agisse d'un site utilisateur ou d'un site de projet, l'enregistrement DNS doit pointer vers votre domaine Pages (`namespace.gitlab.io`), sans aucun chemin.

#### Domaines racines et sous-domaines {#both-root-and-subdomains}

Pour faire pointer à la fois le domaine racine et le sous-domaine vers le même site web, par exemple `example.com` et `www.example.com`, vous avez besoin des éléments suivants :

- Un enregistrement DNS `A` pour le domaine.
- Un enregistrement DNS `AAAA` pour le domaine.
- Un enregistrement DNS `ALIAS`/`CNAME` pour le sous-domaine.
- Un enregistrement DNS `TXT` pour chacun.

| De                                              | Enregistrement DNS | Vers |
|---------------------------------------------------|------------|----|
| `example.com`                                     | `A`        | `35.185.44.232` |
| `example.com`                                     | `AAAA`     | `2600:1901:0:7b8a::` |
| `_gitlab-pages-verification-code.example.com`     | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |
| `www.example.com`                                 | `CNAME`    | `namespace.gitlab.io` |
| `_gitlab-pages-verification-code.www.example.com` | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |

Si vous utilisez Cloudflare, consultez [la redirection de `www.domain.com` vers `domain.com` avec Cloudflare](#redirect-wwwdomaincom-to-domaincom-with-cloudflare).

De plus :

- N'utilisez pas un enregistrement `CNAME` si vous souhaitez faire pointer votre `domain.com` vers votre site GitLab Pages. Utilisez plutôt un enregistrement `A`.
- N'ajoutez pas de caractères spéciaux après le domaine Pages par défaut. Par exemple, ne faites pas pointer `subdomain.domain.com` vers ou `namespace.gitlab.io/`. Certains fournisseurs d'hébergement de domaine peuvent demander un point final (`namespace.gitlab.io.`).
- [Modification](https://about.gitlab.com/blog/gcp-move-update/#gitlab-pages-and-custom-domains) de l'IP de GitLab Pages sur GitLab.com de `52.167.214.135` à `35.185.44.232` en 2018.
- [Ajout](https://gitlab.com/gitlab-org/gitlab/-/issues/214718) de la prise en charge IPv6 sur GitLab.com en 2023.

### Étape 4 :  vérifier la propriété du domaine {#step-4-verify-the-domains-ownership}

Après avoir ajouté tous les enregistrements DNS :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.
1. À côté du nom de domaine, sélectionnez **Modifier** ({{< icon name="pencil" >}}).
1. Dans **État de la vérification**, sélectionnez **Relancer la vérification** ({{< icon name="retry" >}}).

![Paramètres GitLab Pages affichant l'option Relancer la vérification pour un domaine.](img/retry_domain_verification_v18_8.png)

Lorsque votre domaine devient actif, votre site web est accessible via votre nom de domaine.

> [!warning]
> Sur les instances GitLab avec la vérification de domaine activée, GitLab supprime les domaines non vérifiés du projet après 7 jours.

De plus :

- La vérification de domaine est obligatoire pour les utilisateurs de GitLab.com. Pour GitLab Self-Managed, votre administrateur GitLab a la possibilité de [désactiver la vérification des domaines personnalisés](../../../../administration/pages/_index.md#custom-domain-verification).
- [La propagation DNS peut prendre un certain temps (jusqu'à 24 heures)](https://www.inmotionhosting.com/support/domain-names/dns-nameserver-changes/complete-guide-to-dns-records/), bien qu'il s'agisse généralement d'une question de minutes. Jusqu'à ce que cela soit effectif, la vérification échoue et toute tentative d'accès à votre domaine génère une erreur 404.
- Une fois votre domaine vérifié, laissez l'enregistrement de vérification en place. Votre domaine est vérifié périodiquement et pourrait être désactivé si l'enregistrement est supprimé.

## Ajouter d'autres alias de domaine {#add-more-domain-aliases}

Vous pouvez ajouter plusieurs alias (domaines personnalisés et sous-domaines) au même projet. Un alias peut être compris comme plusieurs portes menant à la même pièce.

Tous les alias que vous avez définis pour votre site sont répertoriés dans **Paramètres** > **Pages**. Depuis cette page, vous pouvez les afficher, les ajouter et les supprimer.

## Rediriger `www.domain.com` vers `domain.com` avec Cloudflare {#redirect-wwwdomaincom-to-domaincom-with-cloudflare}

Si vous utilisez Cloudflare, vous pouvez utiliser des règles de page pour rediriger `www.domain.com` vers `domain.com` sans ajouter les deux domaines à GitLab :

1. Dans Cloudflare, créez au moins l'un des éléments suivants :
   - Un enregistrement DNS `A` pointant `domain.com` vers `35.185.44.232`.
   - Un enregistrement DNS `AAAA` pointant `domain.com` vers `2600:1901:0:7b8a::`.
1. Dans GitLab, ajoutez le domaine à GitLab Pages et obtenez le code de vérification.
1. Dans Cloudflare, créez un enregistrement DNS `TXT` pour vérifier votre domaine.
1. Dans GitLab, vérifiez votre domaine.
1. Dans Cloudflare, créez un enregistrement DNS `CNAME` pointant `www` vers `domain.com`.
1. Dans Cloudflare, ajoutez une règle de page faisant pointer `www.domain.com` vers `domain.com` :
   1. Accédez au tableau de bord de votre domaine. Dans la barre de navigation supérieure, sélectionnez **Règles de page**.
   1. Sélectionnez **Créer une règle de page**.
   1. Saisissez le domaine `www.domain.com` et sélectionnez **+ Ajouter un paramètre**.
   1. Dans la liste déroulante, choisissez **URL de transfert**, puis sélectionnez le code de statut **301 - Redirection permanente**.
   1. Saisissez l'URL de destination `https://domain.com`.

## Ajouter un certificat SSL/TLS à Pages {#add-an-ssltls-certificate-to-pages}

Pour sécuriser votre domaine personnalisé avec GitLab Pages, vous pouvez :

- Utiliser l'[intégration Let's Encrypt](lets_encrypt_integration.md) pour obtenir et renouveler automatiquement les certificats SSL.
- Ajouter manuellement des certificats SSL/TLS.

Pour une présentation de la certification SSL/TLS, consultez [Certificats SSL/TLS GitLab Pages](ssl_tls_concepts.md).

### Ajouter manuellement des certificats SSL/TLS {#manually-add-ssltls-certificates}

Prérequis :

- Un site GitLab Pages opérationnel, accessible sur un domaine personnalisé.
- Les composants de certificat suivants :

  - **Certificat PEM** : le certificat généré par l'autorité de certification (CA).
  - **Certificat intermédiaire** : également appelé certificat racine, il identifie l'autorité de certification (CA). Généralement combiné avec le certificat PEM, mais certains certificats comme les [certificats Cloudflare](https://about.gitlab.com/blog/setting-up-gitlab-pages-with-cloudflare-certificates/) nécessitent de les ajouter séparément.
  - **Clé privée** : une clé chiffrée qui valide votre PEM par rapport à votre domaine.

Pour ajouter un certificat lors de la création d'un nouveau domaine :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.
1. Dans le coin supérieur droit, sélectionnez **Nouveau domaine**.
1. Dans **Domaine**, saisissez le nom de domaine.
1. Dans **Certificat**, désactivez le bouton **Gestion automatique des certificats à l'aide de Let's Encrypt**.
1. Remplissez les champs du certificat.
1. Sélectionnez **Créer un nouveau domaine**.

Pour ajouter un certificat à un domaine existant :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.
1. À côté du nom de domaine, sélectionnez **Modifier** ({{< icon name="pencil" >}}).
1. Dans **Certificat**, désactivez le bouton **Gestion automatique des certificats à l'aide de Let's Encrypt**.
1. Remplissez les champs du certificat.
1. Sélectionnez **Enregistrer les modifications**.

Lorsque vous remplissez les champs du certificat :

- Dans **Certificat (PEM)**, collez le certificat PEM. Si votre certificat nécessite un certificat intermédiaire distinct, collez-le dans le même champ, séparé par une ligne vide. Pour plus d'informations, consultez [la configuration de GitLab Pages avec des certificats Cloudflare](https://about.gitlab.com/blog/setting-up-gitlab-pages-with-cloudflare-certificates/).
- Dans le champ de la clé privée, collez votre clé privée.

> [!note]
> N'ouvrez pas les certificats ou les clés de chiffrement dans des éditeurs de texte ordinaires. Utilisez des éditeurs de code tels que Sublime Text, Dreamweaver ou VS Code.

## Forcer le HTTPS pour les sites GitLab Pages {#force-https-for-gitlab-pages-websites}

Vous pouvez forcer le HTTPS pour GitLab Pages afin de rediriger automatiquement les requêtes HTTP vers HTTPS avec une redirection 301. Cela fonctionne avec le domaine GitLab Pages par défaut et les domaines personnalisés disposant d'un certificat valide.

Pour forcer le HTTPS :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.
1. Cochez la case **Forcer le HTTPS (nécessite des certificats valides)**.
1. Sélectionnez **Enregistrer les modifications**.

Si vous utilisez Cloudflare CDN devant GitLab Pages, définissez le paramètre de connexion SSL sur `full` plutôt que sur `flexible`. Pour plus d'informations, consultez les [instructions Cloudflare CDN](https://developers.cloudflare.com/ssl/origin-configuration/ssl-modes#h_4e0d1a7c-eb71-4204-9e22-9d3ef9ef7fef).

## Modifier un domaine personnalisé {#edit-a-custom-domain}

Vous pouvez modifier un domaine personnalisé pour :

- Afficher le domaine personnalisé.
- Afficher l'enregistrement DNS à ajouter.
- Afficher l'entrée de vérification `TXT`.
- Relancer la vérification.
- Modifier les paramètres du certificat.

Pour modifier un domaine personnalisé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.
1. À côté du nom de domaine, sélectionnez **Modifier** ({{< icon name="pencil" >}}).

## Supprimer un domaine personnalisé {#delete-a-custom-domain}

Après la suppression d'un domaine personnalisé, le domaine n'est plus vérifié dans GitLab et ne peut plus être utilisé avec GitLab Pages.

Pour supprimer un domaine personnalisé :

1. Dans la barre supérieure, sélectionnez **Rechercher ou accéder à**, puis recherchez votre projet.
1. Dans la barre latérale gauche, sélectionnez **Déployer** > **Pages**.
1. À côté du nom de domaine, sélectionnez **Supprimer le domaine** ({{< icon name="remove" >}}).
1. Lorsque vous y êtes invité, sélectionnez **Supprimer le domaine**.

## Dépannage {#troubleshooting}

### Vérification de domaine {#domain-verification}

Pour vérifier manuellement que vous avez correctement configuré l'entrée DNS `TXT` de vérification de domaine, vous pouvez exécuter la commande suivante dans votre terminal :

```shell
dig _gitlab-pages-verification-code.<YOUR-PAGES-DOMAIN> TXT
```

Résultat attendu :

```plaintext
;; ANSWER SECTION:
_gitlab-pages-verification-code.<YOUR-PAGES-DOMAIN>. 300 IN TXT "gitlab-pages-verification-code=<YOUR-VERIFICATION-CODE>"
```

Dans certains cas, il peut être utile d'ajouter le code de vérification avec le même nom de domaine que celui que vous essayez d'enregistrer.

Pour un domaine racine :

| De                                          | Enregistrement DNS | Vers |
|-----------------------------------------------|------------|----|
| `example.com`                                 | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |
| `_gitlab-pages-verification-code.example.com` | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |

Pour un sous-domaine :

| De                                              | Enregistrement DNS | Vers |
|---------------------------------------------------|------------|----|
| `www.example.com`                                 | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |
| `_gitlab-pages-verification-code.www.example.com` | `TXT`      | `gitlab-pages-verification-code=00112233445566778899aabbccddeeff` |
