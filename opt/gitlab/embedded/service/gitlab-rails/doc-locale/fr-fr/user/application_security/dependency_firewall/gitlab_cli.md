---
stage: Security Risk Management
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Utiliser la CLI GitLab avec le pare-feu des dépendances
description: Exécutez un gestionnaire de paquets via le pare-feu des dépendances avec les commandes glab df.
---

{{< details >}}

- Édition : GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed
- Statut : version bêta

{{< /details >}}

La [CLI GitLab](../../../editor_extensions/gitlab_cli/_index.md) exécute votre gestionnaire de paquets via le pare-feu des dépendances. Préfixez toute commande de gestionnaire de paquets prise en charge avec `glab dependency-firewall`, ou son alias abrégé `glab df` :

```shell
glab df npm install
glab df pip install requests
glab df maven verify
```

Aucune configuration n'est nécessaire. La CLI lit le projet depuis votre remote Git, s'authentifie avec vos identifiants `glab` existants et utilise le registre que votre gestionnaire de paquets est déjà configuré pour utiliser.

## Prérequis {#prerequisites}

- Installez la [CLI GitLab](../../../editor_extensions/gitlab_cli/_index.md).
- Authentifiez-vous avec `glab auth login`.
- Exécutez la commande depuis un checkout Git dont le remote pointe vers le projet GitLab auquel les politiques s'appliquent.
- Assurez-vous que le binaire du gestionnaire de paquets est présent dans votre `PATH`.

## Fonctionnement des commandes {#how-the-commands-work}

Chaque commande `glab df` exécute le binaire du gestionnaire de paquets et lui transmet tous les arguments tels quels. Pendant l'exécution du gestionnaire, la CLI :

1. Démarre un proxy d'inspection local et y achemine le trafic HTTPS du gestionnaire de paquets.
1. Lit le nom et la version de chaque paquet demandé par le gestionnaire.
1. Demande à GitLab d'évaluer ce paquet par rapport aux politiques de votre projet.
1. Refuse les paquets bloqués avec une réponse `403 Forbidden` et laisse passer les paquets autorisés et avertis.
1. Écrit les paquets bloqués et avertis dans `.gitlab/df/ci-log.json` et affiche un résumé.
1. Quitte avec le code de sortie du gestionnaire de paquets.

La CLI ne modifie pas vos fichiers `.npmrc`, `.yarnrc.yml`, `pip.conf`, `settings.xml`, `~/.gemrc` ni aucune autre configuration de registre. Elle inspecte plutôt le trafic en transit.

Les résultats d'évaluation sont mis en cache pour la durée d'une seule exécution ; ainsi, un paquet apparaissant plusieurs fois dans un arbre de dépendances n'est évalué qu'une seule fois.

La commande se termine avec les codes suivants :

| Code de sortie | Signification |
|-----------|---------|
| Code de sortie du gestionnaire de paquets | Le gestionnaire de paquets s'est exécuté et a terminé. |
| `1`       | Le gestionnaire de paquets est introuvable dans votre `PATH` ou n'a pas pu démarrer. La CLI affiche une erreur. |
| `130`     | L'exécution a été interrompue, par exemple avec <kbd>Control</kbd>+<kbd>C</kbd>. |

La CLI écrit `.gitlab/df/ci-log.json` dans le répertoire de travail à chaque exécution, y compris les exécutions locales, de sorte que le fichier apparaît comme un fichier non suivi dans votre dépôt. Ajoutez `.gitlab/df/` à votre fichier `.gitignore`.

## Lire le résumé d'exécution {#read-the-run-summary}

Après la fin de l'exécution du gestionnaire de paquets, la CLI affiche un tableau de tous les paquets que le pare-feu a avertis ou bloqués :

```plaintext
╭────────────────────────────────────────────────────────────────────╮
│ ✖  GitLab Dependency Firewall                                      │
│ 1 blocked, 1 warning                                               │
├────────────────────────────────────────────────────────────────────┤
│    PACKAGE   VERSION  REASON                                       │
│ ✖  left-pad    1.3.0  Package 'left-pad' violates 'no-gpl' policy  │
│ ▲  lodash    4.17.15  Package 'lodash' violates 'high-risk' policy │
╰────────────────────────────────────────────────────────────────────╯
```

Un `✖` marque un paquet bloqué et un `▲` marque un paquet averti.

Une exécution comportant au moins un paquet bloqué affiche le résumé dans la sortie d'erreur standard. Une exécution avec uniquement des avertissements l'affiche dans la sortie standard. La CLI n'enregistre jamais les paquets autorisés ; ainsi, une exécution sans avertissements ni blocages n'affiche aucun résumé.

## Utiliser le pare-feu en CI/CD {#use-the-firewall-in-cicd}

Préfixez la commande du gestionnaire de paquets dans le script de votre job. Le job échoue lorsque le gestionnaire de paquets échoue, car la CLI propage son code de sortie :

```yaml
install:
  variables:
    GLAB_ENABLE_CI_AUTOLOGIN: "true"
  script:
    - glab df npm ci
```

La CLI se connecte avec le jeton de job CI/CD uniquement lorsque la variable CI/CD `GLAB_ENABLE_CI_AUTOLOGIN` a la valeur `true`. La valeur par défaut est `false`. La CLI requiert également `GITLAB_CI=true`, que GitLab définit dans chaque job. Une fois la variable définie, aucune autre information d'identification n'est nécessaire.

Le jeton de job ne peut évaluer les paquets que pour son propre projet. GitLab refuse un jeton provenant d'un autre projet. L'utilisateur qui a déclenché le job doit disposer au minimum du rôle Reporter sur le projet.

Pour générer un rapport sur l'activité du pare-feu en tant qu'étape distincte, utilisez `glab df ci-summary`. Cette commande lit `.gitlab/df/ci-log.json` et affiche les paquets bloqués et avertis enregistrés par chaque exécution de `glab df` dans ce répertoire :

```yaml
install:
  variables:
    GLAB_ENABLE_CI_AUTOLOGIN: "true"
  script:
    - glab df npm ci
    - glab df pip install -r requirements.txt
  after_script:
    - glab df ci-summary
```

`glab df ci-summary` utilise les codes de sortie suivants :

| Code de sortie | Signification |
|-----------|---------|
| `0`       | Aucun paquet bloqué dans le journal. |
| `1`       | Le journal n'a pas pu être lu. |
| `3`       | Au moins un paquet dans le journal a été bloqué. |

Exécutez `glab df ci-summary` depuis le même répertoire que les commandes `glab df` qui ont écrit le journal. Sinon, la commande ne trouve aucun journal, ne signale aucun blocage et se termine avec `0`.

Les entrées s'accumulent entre les exécutions et la CLI ne les efface jamais. Un blocage provenant d'une exécution antérieure maintient `glab df ci-summary` avec un code de sortie `3` jusqu'à ce que vous supprimiez `.gitlab/df/ci-log.json`. Si le fichier est illisible, la CLI le laisse en place sans l'écraser, et `glab df ci-summary` se termine avec `1`.

Ne restaurez pas le cache du gestionnaire de paquets entre les jobs si vous souhaitez que chaque paquet soit évalué. Les paquets restaurés depuis un cache [ne sont pas évalués](_index.md#restrictions).

## Vérifier un seul paquet {#check-a-single-package}

Utilisez `glab df package` pour vérifier un paquet par rapport aux politiques de votre projet. Cette commande n'exécute pas de gestionnaire de paquets et ne nécessite pas l'installation d'un gestionnaire de paquets. Comme les autres commandes, elle résout le projet depuis votre remote Git.

Transmettez une URL de paquet (PURL) incluant une version. Les types PURL pris en charge sont `npm`, `pypi`, `maven` et `gem` :

```shell
glab df package pkg:npm/left-pad@1.3.0
glab df package pkg:pypi/requests@2.31.0
glab df package pkg:maven/org.slf4j/slf4j-api@2.0.13
glab df package pkg:gem/rails@7.1.3
```

`glab df package` utilise les codes de sortie suivants :

| Code de sortie | Signification |
|-----------|---------|
| `0`       | Le paquet est autorisé ou averti. |
| `1`       | La CLI est mal configurée ou une erreur de transport s'est produite. |
| `3`       | Le paquet est bloqué. |

La commande n'écrit pas dans `.gitlab/df/ci-log.json`, donc `glab df ci-summary` n'inclut pas son résultat.

## Lorsque GitLab ne peut pas évaluer un paquet {#when-gitlab-cant-evaluate-a-package}

La CLI gère une évaluation qui ne peut pas aboutir de deux façons différentes.

### La CLI bloque le paquet {#the-cli-blocks-the-package}

Si la demande d'évaluation échoue, la CLI bloque le paquet. Une demande échoue en raison d'une erreur réseau, d'un délai d'expiration après 60 secondes, d'une erreur de serveur (`503`), d'une limite de débit (`429`) ou d'une erreur de permission (`403`), par exemple lorsque vous ne disposez pas du rôle Reporter. La raison indiquée dans le résumé commence par `policy check failed:`.

La CLI réessaie une vérification échouée la prochaine fois que le paquet est demandé lors de la même exécution.

### La CLI autorise tous les paquets {#the-cli-allows-every-package}

Si GitLab répond que le pare-feu n'évalue pas le projet, la CLI autorise tous les paquets pour le reste de l'exécution. Cela se produit lorsque le pare-feu est désactivé, ou lorsque GitLab ne trouve pas le projet ou que votre jeton ne peut pas y accéder. La CLI affiche une ligne dans la sortie d'erreur standard commençant par `dependency firewall not evaluating`.

Un remote Git mal saisi ou un jeton ne pouvant pas accéder au projet autorise donc tous les paquets. Vérifiez votre sortie pour cette ligne.

## Projets sans pare-feu {#projects-without-the-firewall}

Lorsque le pare-feu n'est pas activé pour un projet, les commandes `glab df` exécutent le gestionnaire de paquets normalement et n'évaluent rien. La CLI affiche une ligne commençant par `dependency firewall not evaluating` dans la sortie d'erreur standard. Vous pouvez utiliser les mêmes commandes dans chaque projet, qu'une politique s'applique ou non.
