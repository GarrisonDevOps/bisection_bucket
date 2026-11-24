---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Découvrez comment utiliser et administrer GitLab, la plateforme Git entièrement intégrée et la plus évolutive pour le développement logiciel."
title: 'GitLab : la plateforme DevSecOps'
---

DevSecOps est une combinaison du développement, de la sécurité et des opérations. Il s'agit d'une approche du développement logiciel qui intègre la sécurité tout au long du cycle de vie du développement.

## DevSecOps comparé à DevOps {#devsecops-compared-to-devops}

DevOps combine le développement et les opérations, avec l'objectif d'améliorer l'efficacité, la rapidité et la sécurité du développement et de la livraison de logiciels.

DevOps signifie travailler ensemble pour concevoir, développer et livrer des logiciels sécurisés à grande vitesse. Les pratiques DevOps incluent l'automatisation, la collaboration, les retours rapides et l'amélioration itérative.

DevSecOps est une évolution de DevOps. DevSecOps intègre les pratiques de sécurité des applications à chaque étape du développement logiciel.

Tout au long du processus de développement, des outils et des méthodes protègent et surveillent vos applications en production. Les nouvelles surfaces d'attaque, comme les conteneurs et les orchestrateurs, doivent également être surveillées et protégées. Les outils DevSecOps automatisent les workflows de sécurité pour créer un processus adaptable à vos équipes de développement et de sécurité, améliorant ainsi la collaboration et supprimant les silos. En intégrant la sécurité dans le cycle de vie du développement logiciel, vous pouvez sécuriser de manière cohérente des processus rapides et itératifs, améliorant l'efficacité sans sacrifier la qualité.

## Fondamentaux de DevSecOps {#devsecops-fundamentals}

Les fondamentaux de DevSecOps incluent :

- Automatisation
- Collaboration
- Garde-fous de politique
- Visibilité

Pour plus de détails, consultez [cet article sur DevSecOps](https://about.gitlab.com/topics/devsecops/).

## DevSecOps en pratique {#devsecops-in-practice}

Les fonctionnalités GitLab suivantes font toutes partie d'une plateforme DevSecOps robuste :

- Sécurité Shift-left : le SAST (test statique de sécurité des applications) et l'analyse des dépendances dans les merge requests détectent les vulnérabilités avant la fusion du code.
- Sécurité des conteneurs : l'analyse d'images pour les CVE, la protection à l'exécution et les politiques de sécurité Kubernetes appliquent le principe du moindre privilège.
- Analyse de l'Infrastructure as Code (IaC) : détection automatisée des mauvaises configurations dans les manifestes Terraform, CloudFormation et Kubernetes.
- Détection des secrets : les hooks pre-commit et les analyses de pipeline CI/CD empêchent les fuites d'informations d'identification dans les dépôts.
- Tableaux de bord de sécurité : suivi centralisé des vulnérabilités avec score CVSS, métriques d'exploitabilité et workflows de remédiation.

## DevSecOps est-il fait pour vous ? {#is-devsecops-right-for-you}

Si votre organisation fait face à l'un des défis suivants, une approche DevSecOps pourrait vous convenir.

<!-- Do not delete the double spaces at the end of these lines. They improve the rendered view. -->

- Les équipes de développement, de sécurité et d'opérations sont cloisonnées. Si le développement et les opérations sont isolés des problèmes de sécurité, ils ne peuvent pas développer de logiciels sécurisés. Et si les équipes de sécurité ne font pas partie du processus de développement, elles ne peuvent pas identifier les risques de manière proactive. DevSecOps rassemble les équipes pour améliorer les workflows et partager les idées. Les organisations pourraient même constater une amélioration du moral et de la rétention des employés.

- Les longs cycles de développement rendent difficile la satisfaction des demandes des clients ou des parties prenantes. L'une des raisons de cette difficulté pourrait être la sécurité. DevSecOps intègre la sécurité à chaque étape du cycle de vie du développement, ce qui signifie qu'une sécurité solide ne nécessite pas l'arrêt complet du processus.

- Vous migrez vers le cloud (ou envisagez de le faire). La migration vers le cloud implique souvent l'adoption de nouveaux processus, outils et systèmes de développement. C'est le moment idéal pour rendre les processus plus rapides et plus sécurisés, et DevSecOps pourrait grandement faciliter cela.

Pour démarrer avec DevSecOps, [apprenez-en davantage et essayez GitLab Ultimate gratuitement](https://about.gitlab.com/solutions/application-security-testing/).
