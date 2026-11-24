---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Noms de domaine par défaut et URL de GitLab Pages
description: Noms de domaine par défaut et structure des URL pour les sites GitLab Pages.
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Pages fournit des noms de domaine par défaut basés sur votre espace de nommage et le nom de votre projet. Ces domaines :

- Génèrent des URL prévisibles pour les sites de projet, les sites utilisateur et les sites de groupe.
- Prennent en charge les chemins hiérarchiques qui reflètent la structure organisationnelle de votre instance GitLab.
- Créent des noms de domaine uniques avec des redirections automatiques lorsque cette option est activée.
- Fonctionnent de façon transparente avec des noms de domaine personnalisés et des certificats SSL/TLS.
- S'adaptent aux projets d'utilisateurs, de groupes et de sous-groupes.

Utilisez ces URL pour configurer votre générateur de site statique.

## Noms de domaine par défaut de GitLab Pages {#gitlab-pages-default-domain-names}

{{< history >}}

- [Modification](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163523) : les URL de domaine unique sont désormais plus courtes dans GitLab 17.4.

{{< /history >}}

Si vous utilisez votre propre instance GitLab pour déployer votre site avec GitLab Pages, vérifiez votre domaine générique Pages auprès de votre administrateur système. Ce guide est valable pour toute instance GitLab, à condition de remplacer le domaine générique Pages sur GitLab.com (`*.gitlab.io`) par le vôtre.

Si vous configurez un projet GitLab Pages sur GitLab, celui-ci est automatiquement accessible sous un sous-domaine de `namespace.example.io`. Le [`namespace`](../../namespace/_index.md) est défini par votre nom d'utilisateur sur GitLab.com, ou par le nom du groupe sous lequel vous avez créé ce projet. Pour GitLab Self-Managed, remplacez `example.io` par le domaine Pages de votre instance. Pour GitLab.com, les domaines Pages sont `*.gitlab.io`.

| Type de GitLab Pages | Exemple de chemin d'un projet dans GitLab | URL du site Web |
| -------------------- | ------------ | ----------- |
| Pages utilisateur  | `username/username.example.io`  | `http(s)://username.example.io`  |
| Pages de groupe | `acmecorp/acmecorp.example.io` | `http(s)://acmecorp.example.io` |
| Pages de projet appartenant à un utilisateur  | `username/my-website` | `http(s)://username.example.io/my-website` |
| Pages de projet appartenant à un groupe | `acmecorp/webshop` | `http(s)://acmecorp.example.io/webshop`|
| Pages de projet appartenant à un sous-groupe | `acmecorp/documentation/product-manual` | `http(s)://acmecorp.example.io/documentation/product-manual`|

Lorsque le paramètre **Utiliser un domaine unique** est activé, Pages construit le nom de domaine à partir du nom de projet aplati et d'un identifiant unique de six caractères. Les utilisateurs reçoivent un statut `308 Permanent Redirect` qui redirige le navigateur vers ces URL de domaine unique. Les navigateurs peuvent mettre cette redirection en cache :

| Type de GitLab Pages              | Exemple de chemin d'un projet dans GitLab     | URL du site Web |
| --------------------------------- | --------------------------------------- | ----------- |
| Pages utilisateur                        | `username/username.example.io`          | `http(s)://username-example-io-123456.example.io` |
| Pages de groupe                       | `acmecorp/acmecorp.example.io`          | `http(s)://acmecorp-example-io-123456.example.io` |
| Pages de projet appartenant à un utilisateur     | `username/my-website`                   | `https://my-website-123456.gitlab.io/` |
| Pages de projet appartenant à un groupe    | `acmecorp/webshop`                      | `http(s)://webshop-123456.example.io/` |
| Pages de projet appartenant à un sous-groupe | `acmecorp/documentation/product-manual` | `http(s)://product-manual-123456.example.io/` |

`123456` dans les exemples d'URL est un identifiant unique de six caractères. Par exemple, si l'identifiant unique est `f85695`, le dernier exemple est `http(s)://product-manual-f85695.example.io/`.

> [!warning]
> Pour connaître les limitations relatives aux espaces de nommage servis sous le nom de domaine général et HTTPS, consultez [Sous-domaines de sous-domaines](introduction.md#subdomains-of-subdomains).

Les exemples suivants illustrent le fonctionnement des domaines Pages.

> [!note]
> Les exemples suivants supposent que vous avez désactivé le paramètre **Utiliser un domaine unique**. Si ce n'est pas le cas, reportez-vous au tableau précédent en remplaçant `example.io` par `gitlab.io`.

### Exemples de sites web de projet {#project-website-examples}

- Vous avez créé un projet appelé `blog` sous votre nom d'utilisateur `john`, par conséquent l'URL de votre projet est `https://gitlab.com/john/blog/`. Après avoir activé GitLab Pages pour ce projet et créé votre site, vous pouvez y accéder à l'adresse `https://john.gitlab.io/blog/`.
- Vous avez créé un groupe pour tous vos sites web appelé `websites`, et un projet dans ce groupe est appelé `blog`. L'URL de votre projet est `https://gitlab.com/websites/blog/`. Après avoir activé GitLab Pages pour ce projet, le site est disponible à l'adresse `https://websites.gitlab.io/blog/`.
- Vous avez créé un groupe pour votre département d'ingénierie appelé `engineering`, un sous-groupe pour tous vos sites web de documentation appelé `docs`, et un projet dans ce sous-groupe est appelé `workflows`. L'URL de votre projet est `https://gitlab.com/engineering/docs/workflows/`. Après avoir activé GitLab Pages pour ce projet, le site est disponible à l'adresse `https://engineering.gitlab.io/docs/workflows`.

### Exemples de sites web d'utilisateur et de groupe {#user-and-group-website-examples}

- Sous votre nom d'utilisateur, `john`, vous avez créé un projet appelé `john.gitlab.io`. L'URL de votre projet est `https://gitlab.com/john/john.gitlab.io`. Après avoir activé GitLab Pages pour votre projet, votre site web est publié à l'adresse `https://john.gitlab.io`.
- Sous votre groupe `websites`, vous avez créé un projet appelé `websites.gitlab.io`. L'URL de votre projet est `https://gitlab.com/websites/websites.gitlab.io`. Après avoir activé GitLab Pages pour votre projet, votre site web est publié à l'adresse `https://websites.gitlab.io`.

**Exemple général** :

- Sur GitLab.com, un site de projet est toujours disponible à l'adresse `https://namespace.gitlab.io/project-slug`
- Sur GitLab.com, un site web d'utilisateur ou de groupe est disponible à l'adresse `https://namespace.gitlab.io/`
- Sur votre instance GitLab, remplacez `gitlab.io` par le domaine de votre serveur Pages. Demandez cette information à votre administrateur système.

## URL et URL de base {#urls-and-base-urls}

> [!note]
> L'option `baseurl` peut porter un nom différent selon les générateurs de sites statiques.

La configuration par défaut de tout générateur de site statique (SSG) s'attend à trouver votre site web sous un (sous-)domaine (`example.com`), et non dans un sous-répertoire de ce domaine (`example.com/subdir`). Par conséquent, chaque fois que vous publiez un site de projet (par exemple, `namespace.gitlab.io/project-slug`), vous devez rechercher cette configuration (URL de base) dans la documentation de votre générateur de site statique et la configurer pour refléter ce modèle.

Par exemple, pour un site Jekyll, le `baseurl` est défini dans le fichier de configuration Jekyll, `_config.yml`. Si l'URL de votre site web est `https://john.gitlab.io/blog/`, vous devez ajouter cette ligne à `_config.yml` :

```yaml
baseurl: "/blog"
```

Si vous déployez votre site web après avoir dupliqué l'un des [exemples par défaut](https://gitlab.com/pages), le `baseurl` est déjà configuré de cette façon. Tous les exemples sont des sites web de projet. Si vous décidez d'en faire un site web d'utilisateur ou de groupe, vous devez supprimer cette configuration de votre projet. Pour l'exemple Jekyll, modifiez le fichier Jekyll `_config.yml` comme suit :

```yaml
baseurl: ""
```

Si vous utilisez l'[exemple HTML simple](https://gitlab.com/pages/plain-html), vous n'avez pas besoin de définir un `baseurl`.

## Domaines personnalisés {#custom-domains}

GitLab Pages prend en charge les domaines et sous-domaines personnalisés, servis via HTTP ou HTTPS. Consultez [Domaines personnalisés et certificats SSL/TLS pour GitLab Pages](custom_domains_ssl_tls_certification/_index.md) pour plus d'informations.
