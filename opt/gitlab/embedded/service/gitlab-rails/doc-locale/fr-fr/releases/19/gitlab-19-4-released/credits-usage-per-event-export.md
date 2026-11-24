---
title: "Détail par événement dans l'export d'utilisation des crédits"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: fulfillment
documentation_link: "../../../subscriptions/gitlab_credits_dashboard/#export-usage-data"
work_item: https://gitlab.com/gitlab-org/customers-gitlab-com/-/work_items/18963
categories: [ Consumables Cost Management ]
level: secondary
---

L'export d'utilisation des crédits vous fournissait une ligne par jour, indiquant le montant dépensé par un abonnement, mais pas ce sur quoi il avait été dépensé. Attribuer des crédits à une équipe, un projet ou une seule automatisation relevait de la conjecture.

L'export renvoie désormais un fichier ZIP contenant deux fichiers CSV : le récapitulatif quotidien déjà disponible, et un fichier par événement avec une ligne pour chaque événement facturable. Chaque ligne inclut le produit, le type de flow, la session, l'utilisateur, l'espace de nommage, le projet, les crédits utilisés et le nombre de tokens. Les exports s'exécutent en arrière-plan, et GitLab vous envoie par e-mail un lien de téléchargement lorsque le fichier est prêt.
