---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Utiliser un projet comme package Go
description: "Modules Go et appels d'importation."
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- Modifié dans [GitLab 17.3](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/161162) pour retourner des erreurs 404 pour les requêtes `go get` non autorisées.
- Modifié dans [GitLab 19.4](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250766) pour prendre en charge les jetons d'accès personnels à granularité fine.

{{< /history >}}

Prérequis :

- Pour utiliser un projet privé dans un sous-groupe comme package Go, vous devez [authentifier les requêtes Go](#authenticate-go-requests-to-private-projects). Les requêtes Go non authentifiées entraînent l'échec de `go get`. Vous n'avez pas besoin d'authentifier les requêtes Go pour les projets qui ne se trouvent pas dans des sous-groupes.

Pour utiliser un projet comme package Go, utilisez les requêtes de découverte `go get` et `godoc.org`. Vous pouvez utiliser les balises meta :

- [`go-import`](https://pkg.go.dev/cmd/go#hdr-Remote_import_paths)
- [`go-source`](https://github.com/golang/gddo/wiki/Source-Code-Links)

> [!note]
> Si vous effectuez une requête `go get` avec des identifiants HTTP non valides, vous recevez une erreur 404. Vous pouvez trouver les identifiants HTTP dans `~/.netrc` (MacOS et Linux) ou `~/_netrc` (Windows). Dans Go 1.24 et les versions ultérieures, vous pouvez également utiliser la variable d'environnement `GOAUTH` pour fournir des identifiants. Pour plus d'informations, consultez [l'authentification avec `GOAUTH`](#authenticate-with-goauth).

## Authentifier les requêtes Go pour les projets privés {#authenticate-go-requests-to-private-projects}

Prérequis :

- Votre instance GitLab doit être accessible via HTTPS.
- Vous devez disposer de l'un des éléments suivants :
  - Un [jeton d'accès personnel](../profile/personal_access_tokens.md) avec la portée `read_api`.
  - Un [jeton d'accès personnel à granularité fine](../../auth/tokens/fine_grained_access_tokens.md) avec l'autorisation de téléchargement pour la ressource Code, limité au projet.

### S'authentifier avec `GOAUTH` {#authenticate-with-goauth}

Dans Go 1.24 et les versions ultérieures, utilisez la [variable d'environnement `GOAUTH`](https://pkg.go.dev/cmd/go@master#hdr-GOAUTH_environment_variable) pour fournir des identifiants avec une commande personnalisée.

> [!note]
> La valeur `git dir` pour `GOAUTH` ne fonctionne pas pour les projets privés dans des sous-groupes imbriqués avec une profondeur supérieure à 1. Utilisez plutôt une commande personnalisée.

Pour s'authentifier avec `GOAUTH`, créez une commande personnalisée qui ajoute un en-tête d'authentification HTTP Basic aux requêtes Go. L'exemple suivant utilise vos identifiants Git via HTTPS, renvoyés par `git credential fill`, pour authentifier les requêtes vers `gitlab.com` :

```shell
#!/usr/bin/env bash
GITLAB_URL="https://gitlab.com"

creds=$(echo "url=${GITLAB_URL}" | git credential fill 2>&1) || {
  printf >&2 'error: git credential fill failed:\n%s\n' "$creds"
  exit 1
}

username=""
password=""
while IFS='=' read -r key value; do
  case "$key" in
    username) username="$value" ;;
    password) password="$value" ;;
  esac
done <<< "$creds"

if [ -z "$username" ] || [ -z "$password" ]; then
  printf >&2 'error: git credential fill did not return a username or password for %s\n' "$GITLAB_URL"
  exit 1
fi

encoded=$(printf '%s:%s' "$username" "$password" | base64 | tr -d '\n')

# Expected output format: https://pkg.go.dev/cmd/go@master#hdr-GOAUTH_environment_variable
printf '%s\n\nAuthorization: Basic %s\n\n' "$GITLAB_URL" "$encoded"
```

Pour utiliser ce script :

1. Enregistrez le script dans un fichier, par exemple `gitlab_goauth.sh`.
1. Rendez le fichier exécutable :

   ```shell
   chmod +x gitlab_goauth.sh
   ```

1. Définissez la variable d'environnement `GOAUTH` sur le chemin absolu de votre commande :

   ```shell
   export GOAUTH="<absolute_path_to_your_command>"
   ```

Vous pouvez également utiliser votre fichier `.netrc` existant avec `GOAUTH` :

```shell
export GOAUTH="netrc"
```

### S'authentifier avec `.netrc` {#authenticate-with-netrc}

Pour authentifier les requêtes Go avec un fichier [`.netrc`](https://everything.curl.dev/usingcurl/netrc.html), créez le fichier avec les informations suivantes :

```plaintext
machine gitlab.example.com
login <gitlab_user_name>
password <personal_access_token>
```

Sur Windows, Go lit `~/_netrc` au lieu de `~/.netrc`.

La commande `go` ne transmet pas les identifiants via des connexions non sécurisées. Elle authentifie les requêtes HTTPS effectuées par Go, mais n'authentifie pas les requêtes effectuées via Git.

## Authentifier les requêtes Git {#authenticate-git-requests}

Si Go ne peut pas récupérer un module depuis un proxy, il utilise Git. Git utilise un fichier `.netrc` pour authentifier les requêtes, mais vous pouvez configurer d'autres méthodes d'authentification.

Configurez Git pour :

- Intégrer les identifiants dans l'URL de la requête :

  ```shell
  git config --global url."https://${user}:${personal_access_token}@gitlab.example.com".insteadOf "https://gitlab.example.com"
  ```

- Utiliser SSH au lieu de HTTPS :

  ```shell
  git config --global url."git@gitlab.example.com:".insteadOf "https://gitlab.example.com/"
  ```

## Désactiver la récupération des modules Go pour les projets privés {#disable-go-module-fetching-for-private-projects}

Pour récupérer des modules ou des packages, Go utilise les variables d'environnement :

- `GOPRIVATE`
- `GONOPROXY`
- `GONOSUMDB`

Pour désactiver la récupération :

1. Désactivez `GOPRIVATE` :
   - Pour désactiver les requêtes pour un seul projet, désactivez `GOPRIVATE=gitlab.example.com/my/private/project`.
   - Pour désactiver les requêtes pour tous les projets sur GitLab.com, désactivez `GOPRIVATE=gitlab.example.com`.
1. Désactivez les requêtes proxy dans `GONOPROXY`.
1. Désactivez les requêtes de somme de contrôle dans `GONOSUMDB`.

- Si le nom du module ou son préfixe se trouve dans `GOPRIVATE` ou `GONOPROXY`, Go n'interroge pas les proxies de modules.
- Si le nom du module ou son préfixe se trouve dans `GOPRIVATE` ou `GONOSUMDB`, Go n'interroge pas les bases de données de sommes de contrôle.

## Authentifier les requêtes Git pour les sous-groupes privés {#authenticate-git-requests-to-private-subgroups}

Si le module Go se trouve dans un sous-groupe privé tel que `gitlab.com/namespace/subgroup/go-module`, l'authentification Git ne fonctionne pas. Cela se produit parce que `go get` effectue une requête non authentifiée pour découvrir le chemin du dépôt. Sans authentification, GitLab répond avec `gitlab.com/namespace/subgroup.git` pour éviter le risque de sécurité lié à l'exposition de l'existence du projet aux utilisateurs non authentifiés. Par conséquent, le module Go ne peut pas être téléchargé.

Vous pouvez [configurer l'authentification Go](#authenticate-go-requests-to-private-projects) pour télécharger des modules Go dans des sous-groupes privés.

### Solution de contournement : utiliser `.git` dans le nom du module {#workaround-use-git-in-the-module-name}

Il existe un moyen d'ignorer une requête `go get` et de forcer Go à utiliser directement l'authentification Git, mais cela nécessite une modification du nom du module. [D'après la documentation Go](https://go.dev/ref/mod#vcs-find) :

> Si le chemin du module comporte un qualificateur VCS (l'un des suivants : `.bzr`, `.fossil`, `.git`, `.hg`, `.svn`) à la fin d'un composant de chemin, la commande go utilisera tout ce qui précède ce qualificateur de chemin comme URL du dépôt. Par exemple, pour le module `example.com/foo.git/bar`, la commande go télécharge le dépôt à l'adresse `example.com/foo.git` en utilisant Git, en s'attendant à trouver le module dans le sous-répertoire bar.

1. Accédez à `go.mod` du module Go dans un sous-groupe privé.
1. Ajoutez `.git` au nom du module. Par exemple, renommez `module gitlab.com/namespace/subgroup/go-module` en `module gitlab.com/namespace/subgroup/go-module.git`.
1. Committez et poussez cette modification.
1. Consultez les projets Go qui dépendent de ce module et ajustez leurs appels `import`. Par exemple, `import gitlab.com/namespace/subgroup/go-module.git`.

Le module Go devrait être correctement récupéré après cette modification. Par exemple, `GOPRIVATE=gitlab.com/namespace/* go mod tidy`.

## Récupérer des modules Go depuis les sites secondaires Geo {#fetch-go-modules-from-geo-secondary-sites}

Utilisez [Geo](../../administration/geo/_index.md) pour accéder aux dépôts Git contenant des modules Go sur les serveurs Geo secondaires.

Vous pouvez utiliser SSH ou HTTP pour accéder au serveur Geo secondaire.

### Utiliser SSH pour accéder au serveur Geo secondaire {#use-ssh-to-access-the-geo-secondary-server}

Pour accéder au serveur Geo secondaire avec SSH :

1. Reconfigurez Git sur le client pour envoyer le trafic du site principal vers le site secondaire :

   ```shell
   git config --global url."git@gitlab-secondary.example.com".insteadOf "https://gitlab.example.com"
   git config --global url."git@gitlab-secondary.example.com".insteadOf "http://gitlab.example.com"
   ```

   - Pour `gitlab.example.com`, utilisez le nom de domaine du site principal.
   - Pour `gitlab-secondary.example.com`, utilisez le nom de domaine du site secondaire.

1. Assurez-vous que le client est configuré pour l'accès SSH aux dépôts GitLab. Vous pouvez tester cela sur le site principal, et GitLab réplique la clé publique vers le site secondaire.

La requête `go get` génère du trafic HTTP vers le serveur Geo principal. Lorsque le téléchargement du module commence, la configuration `insteadOf` envoie le trafic vers le serveur Geo secondaire.

### Utiliser HTTP pour accéder au site Geo secondaire {#use-http-to-access-the-geo-secondary}

Vous devez utiliser des jetons d'accès persistants qui se répliquent vers le serveur secondaire. Vous ne pouvez pas utiliser les jetons de job CI/CD pour récupérer des modules Go avec HTTP.

Pour accéder au serveur Geo secondaire avec HTTP :

1. Ajoutez une redirection Git `insteadOf` sur le client :

   ```shell
   git config --global url."https://gitlab-secondary.example.com".insteadOf "https://gitlab.example.com"
   ```

   - Pour `gitlab.example.com`, utilisez le nom de domaine du site principal.
   - Pour `gitlab-secondary.example.com`, utilisez le nom de domaine du site secondaire.

1. Générez un [jeton d'accès personnel](../profile/personal_access_tokens.md) et ajoutez les identifiants dans le fichier `~/.netrc` du client :

   ```shell
   machine gitlab.example.com login USERNAME password TOKEN
   machine gitlab-secondary.example.com login USERNAME password TOKEN
   ```

La requête `go get` génère du trafic HTTP vers le serveur Geo principal. Lorsque le téléchargement du module commence, la configuration `insteadOf` envoie le trafic vers le serveur Geo secondaire.
