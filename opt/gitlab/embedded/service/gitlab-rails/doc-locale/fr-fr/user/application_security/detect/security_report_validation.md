---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Validation des rapports de sécurité
---

{{< details >}}

- Édition : Gratuite, GitLab Premium, GitLab Ultimate
- Offre : GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Les rapports de sécurité sont validés avant que leur contenu ne soit ajouté à la base de données. Cela empêche l'ingestion de données de vulnérabilité incorrectes dans la base de données. Les rapports dont la validation échoue sont listés dans l'onglet **Sécurité** du pipeline avec le message d'erreur de validation.

La validation est effectuée par rapport aux [schémas de rapport](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/tree/master/dist), selon la version de schéma déclarée dans le rapport :

- Si le rapport de sécurité spécifie une version de schéma prise en charge, GitLab utilise cette version pour effectuer la validation.
- Si le rapport de sécurité utilise une version dépréciée, GitLab tente de le valider par rapport à cette version et ajoute un avertissement de dépréciation au résultat de la validation.
- Si le rapport de sécurité utilise une version MAJEURE-MINEURE prise en charge du schéma de rapport, mais que la version PATCH ne correspond à aucune des versions intégrées, GitLab tente de le valider par rapport à la dernière version PATCH intégrée du schéma.
  - Exemple : le rapport de sécurité utilise la version 14.1.1 mais la dernière version intégrée est la 14.1.0. GitLab effectuerait la validation par rapport à la version de schéma 14.1.0.
- Si le rapport de sécurité utilise une version qui n'est pas prise en charge, GitLab tente de le valider par rapport à la version de schéma la plus ancienne disponible dans votre installation, mais n'ingère pas le rapport.
- Si le rapport de sécurité ne spécifie pas de version de schéma, GitLab tente de le valider par rapport à la version de schéma la plus ancienne disponible dans GitLab. Étant donné que la propriété `version` est obligatoire, la validation échoue toujours dans ce cas, mais d'autres erreurs de validation peuvent également être présentes.

Pour plus d'informations sur les versions de schéma prises en charge et dépréciées, consultez le [code source du validateur de schéma](https://gitlab.com/gitlab-org/ruby/gems/gitlab-security_report_schemas/-/blob/main/supported_versions).
