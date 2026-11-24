---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Bannissements bloquant un client après des échecs répétés de demandes d'authentification."
title: "Bannissements pour abus et échecs d'authentification"
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Certaines protections bloquent un client pendant une période de temps au lieu de ralentir les requêtes.

## Bannissement pour échec d'authentification pour Git et le registre de conteneurs {#failed-authentication-ban-for-git-and-container-registry}

Par défaut, GitLab retourne le code de statut HTTP `403` pendant 1 heure si 10 demandes d'authentification échouées ont été reçues en 1 minute depuis une seule adresse IP. Ces trois valeurs sont configurables. Cela s'applique uniquement aux éléments combinés suivants :

- Requêtes Git.
- Requêtes du registre de conteneurs (`/jwt/auth`).

Cette limitation :

- Est réinitialisé par les requêtes qui s'authentifient avec succès, jusqu'au début d'un bannissement. Par exemple, 9 demandes d'authentification échouées suivies d'1 requête réussie, puis de 9 nouvelles demandes d'authentification échouées ne déclencheraient pas de bannissement.
- Ne peut pas être effacé en s'authentifiant une fois qu'un bannissement a commencé. Le bannissement est vérifié avant les informations d'identification, de sorte qu'une adresse IP bannie reçoit `403` même avec des informations d'identification valides, jusqu'à l'expiration du bannissement.
- Ne s'applique pas aux requêtes JWT authentifiées par `gitlab-ci-token`.
- Est désactivé par défaut.

Aucun en-tête de réponse n'est fourni.

Pour éviter d'être soumis à une limite de débit, vous pouvez :

- Échelonner l'exécution de vos pipelines automatisés.
- Configurer [le backoff exponentiel et la nouvelle tentative](https://docs.aws.amazon.com/prescriptive-guidance/latest/cloud-design-patterns/retry-backoff.html) pour les tentatives d'authentification échouées.
- Utiliser un processus documenté et les [bonnes pratiques](https://about.gitlab.com/blog/access-token-lifetime-limits/#how-to-minimize-the-impact) pour gérer l'expiration des jetons.

Pour les informations de configuration, consultez [les options de configuration du package Linux](https://docs.gitlab.com/omnibus/settings/configuration/#configure-a-failed-authentication-ban).

## Dépannage {#troubleshooting}

### Rack Attack place le load balancer sur la liste de refus {#rack-attack-is-denylisting-the-load-balancer}

Rack Attack peut bloquer votre load balancer si tout le trafic semble provenir de celui-ci. Dans ce cas, vous devez :

1. [Configurer `nginx[real_ip_trusted_addresses]`](https://docs.gitlab.com/omnibus/settings/nginx/#configure-gitlab-trusted-proxies-and-nginx-real_ip-module). Cela empêche les adresses IP des utilisateurs d'être répertoriées comme les adresses IP du load balancer.
1. Ajouter les adresses IP du load balancer à la liste d'autorisation.
1. Reconfigurez GitLab :

   ```shell
   sudo gitlab-ctl reconfigure
   ```

### Supprimer les adresses IP bloquées de Rack Attack avec Redis {#remove-blocked-ips-from-rack-attack-with-redis}

Pour supprimer une adresse IP bloquée :

1. Recherchez les adresses IP qui ont été bloquées dans le journal de production :

   ```shell
   grep "Rack_Attack" /var/log/gitlab/gitlab-rails/auth.log
   ```

1. La liste de refus est stockée dans l'instance Redis de limitation de débit ; vous devez donc ouvrir `redis-cli` contre celle-ci. Sur une installation qui ne sépare pas les instances, il s'agit de l'instance Redis par défaut :

   ```shell
   /opt/gitlab/embedded/bin/redis-cli -s /var/opt/gitlab/redis/redis.socket
   ```

   Si vous avez configuré `gitlab_rails['redis_rate_limiting_instance']`, connectez-vous à cette instance à la place. La suppression de la clé à partir d'une mauvaise instance semble réussir mais laisse le bannissement en place.

1. Vous pouvez supprimer le blocage en utilisant la syntaxe suivante, en remplaçant `<ip>` par l'adresse IP réelle qui est sur la liste de refus :

   ```plaintext
   del cache:gitlab:rack::attack:allow2ban:ban:<ip>
   ```

1. Confirmez que la clé avec l'adresse IP n'apparaît plus :

   ```plaintext
   keys *rack::attack*
   ```

   Par défaut, [la commande `keys` est désactivée](https://docs.gitlab.com/omnibus/settings/redis/#renamed-commands).

1. Le cas échéant, ajoutez [l'adresse IP à la liste d'autorisation](https://docs.gitlab.com/omnibus/settings/configuration/#configure-a-failed-authentication-ban) pour éviter qu'elle soit à nouveau placée sur la liste de refus.
