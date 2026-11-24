---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Enregistrements DNS de GitLab Pages
description: Enregistrements DNS utilisés pour pointer un domaine personnalisé vers un site GitLab Pages.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Un service web DNS (Domain Name System) redirige les visiteurs vers les sites web en traduisant les noms de domaine (tels que `www.example.com`) en adresses IP numériques (telles que `192.0.2.1`) que les ordinateurs utilisent pour se connecter les uns aux autres.

Un enregistrement DNS est créé pour pointer un (sous-)domaine vers un emplacement donné, qui peut être une adresse IP ou un autre domaine. Si vous souhaitez utiliser GitLab Pages avec votre propre (sous-)domaine, vous devez accéder au panneau de contrôle du bureau d'enregistrement de votre domaine pour ajouter un enregistrement DNS le faisant pointer vers votre site GitLab Pages.

La façon d'ajouter des enregistrements DNS dépend du serveur sur lequel votre domaine est hébergé. Chaque panneau de contrôle dispose de son propre emplacement pour effectuer cette opération. Si vous n'êtes pas administrateur de votre domaine et n'avez pas accès à votre bureau d'enregistrement, vous devez demander au support technique de votre service d'hébergement de le faire pour vous.

Pour plus d'informations, consultez [configurer les enregistrements DNS pour GitLab Pages](_index.md#step-3-set-up-dns-records).

Pour les services d'hébergement les plus populaires, consultez les instructions suivantes :

<!-- vale gitlab_base.Spelling = NO -->

- [123-reg](https://www.123-reg.co.uk/support/domains/domain-name-server-dns-management-guide/)
- [Amazon](https://docs.aws.amazon.com/AmazonS3/latest/userguide/website-hosting-custom-domain-walkthrough.html)
- [Bluehost](https://www.bluehost.com/help/article/dns-management-add-edit-or-delete-dns-entries)
- [Cloudflare](https://developers.cloudflare.com/fundamentals/account/)
- [cPanel](https://docs.cpanel.net/cpanel/domains/zone-editor/)
- [DigitalOcean](https://docs.digitalocean.com/products/networking/dns/how-to/manage-records/)
- [DreamHost](https://help.dreamhost.com/hc/en-us/articles/360035516812-Adding-custom-DNS-records)
- [Gandi](https://docs.gandi.net/en/domain_names/faq/dns_records.html)
- [Go Daddy](https://www.godaddy.com/help/add-an-a-record-19238)
- [Hostgator](https://www.hostgator.com/help/article/changing-dns-records)
- [Inmotion hosting](https://www.inmotionhosting.com/support/edu/cpanel/how-do-i-make-custom-dns-records/)
- [Microsoft](https://learn.microsoft.com/en-us/windows-server/networking/dns/manage-resource-records?tabs=powershell)
- [Namecheap](https://www.namecheap.com/support/knowledgebase/subcategory/2237/host-records-setup/)

<!-- vale gitlab_base.Spelling = YES -->

Si votre service d'hébergement n'est pas répertorié, vous pouvez effectuer une recherche sur le web pour `how to add dns record on <my hosting service>`.

## Enregistrement `A` {#a-record}

Un enregistrement DNS `A` associe un hôte à une adresse IP IPv4. Il pointe un domaine racine tel que `example.com` vers l'adresse IP de l'hôte, telle que `192.0.2.1`.

Exemple :

- `example.com` => `A` => `192.0.2.1`

## Enregistrement `AAAA` {#aaaa-record}

Un enregistrement DNS `AAAA` associe un hôte à une adresse IP IPv6. Il pointe un domaine racine tel que `example.com` vers l'adresse IP de l'hôte, telle que `2001:db8::1`.

Exemple :

- `example.com` => `AAAA` => `2001:db8::1`

## Enregistrement `CNAME` {#cname-record}

Les enregistrements `CNAME` définissent un alias pour le nom canonique de votre serveur (celui défini par un enregistrement `A`). Il pointe un sous-domaine vers un autre domaine.

Exemple :

- `www` => `CNAME` => `example.com`

Ainsi, les visiteurs qui accèdent à `www.example.com` sont redirigés vers `example.com`.

## Enregistrement `MX` {#mx-record}

Les enregistrements MX servent à définir les serveurs de messagerie utilisés pour le domaine. Cela permet aux messages électroniques d'arriver correctement sur votre serveur de messagerie.

Exemple :

- `MX` => `mail.example.com`

Vous pouvez ensuite enregistrer des adresses e-mail pour `users@mail.example.com`.

## Enregistrement `TXT` {#txt-record}

Un enregistrement `TXT` peut associer du texte arbitraire à un hôte ou à un autre nom. Son utilisation la plus courante est la vérification de site.

Exemple :

- `example.com` => `TXT` => `"google-site-verification=6P08Ow5E-8Q0m6vQ7FMAqAYIDprkVV8fUf_7hZ4Qvc8"`

Vous pouvez ainsi vérifier la propriété de ce nom de domaine.

## Tous combinés {#all-combined}

Vous pouvez avoir un seul enregistrement DNS ou plusieurs combinés :

- `example.com` => `A` => `192.0.2.1`
- `example.com` => `AAAA` => `2001:db8::1`
- `www` => `CNAME` => `example.com`
- `MX` => `mail.example.com`
- `example.com` => `TXT` => `"google-site-verification=6P08Ow5E-8Q0m6vQ7FMAqAYIDprkVV8fUf_7hZ4Qvc8"`
