---
title: GitLab Runner 19.5
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.5&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

Nous publions également GitLab Runner 19.5 aujourd'hui ! GitLab Runner est l'agent de build hautement évolutif qui exécute vos jobs CI/CD et envoie les résultats à une instance GitLab. GitLab Runner fonctionne en conjonction avec GitLab CI/CD, le service d'intégration continue open source inclus avec GitLab.

**Nouveautés**

- [Message d'erreur plus clair pour l'exécuteur Kubernetes lorsque le conteneur helper est tué par OOM](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39842)
- [Journalisation du modèle de CPU de l'environnement d'exécution du job au démarrage du job](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39814)

**Corrections de bugs**

- [Les services IPv4 uniquement échouent sur les réseaux à double pile car le contrôle de santé du service Docker ne compose que la dernière adresse résolue](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39939)
- [Les tokens de runner et de job avec un préfixe d'instance ne sont pas reconnus](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39938)
- [L'exécuteur Kubernetes envoie une requête `LIST` d'événements non paginée à chaque interrogation, saturant l'API Priority and Fairness sur les clusters chargés](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39848)
- [L'exécuteur Docker applique `mac_address` aux conteneurs de service au lieu de l'appliquer uniquement au conteneur de build](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39803)
- [`RUNNER_AFTER_SCRIPT_TIMEOUT` est réinitialisé à 5 minutes lorsqu'il dépasse le délai d'expiration du job](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39717)
- [L'envoi du cache échoue avec `403` sur les serveurs S3 qui appliquent les règles SigV4 d'en-têtes signés car `cache_archiver` envoie un `Content-Type` que l'URL présignée ne signe pas](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39701)
- [L'exécuteur Kubernetes définit toujours un objet `resources` vide au niveau du pod, provoquant une mauvaise classification QoS `BestEffort` sur Kubernetes 1.34 et versions ultérieures](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39671)
- [Le serveur local step-runner signale qu'il est prêt avant que son serveur gRPC ne soit en écoute](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39653)
- [La configuration d'arrêt progressif `systemd` documentée arrête la VM en cours d'exécution pour les exécuteurs VirtualBox, Parallels et SSH](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39563)
- [`proxy_exec` affiche l'aide du binaire helper et quitte au lieu d'exécuter le job lorsque l'image possède un `ENTRYPOINT` à plusieurs arguments](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39452)
- [L'exécuteur Docker ignore le paramètre `platform` lorsque plusieurs plateformes d'une même image sont téléchargées](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/38514)

La liste de toutes les modifications se trouve dans le [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-5-stable/CHANGELOG.md) de GitLab Runner.
