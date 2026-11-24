---
stage: AI Platform
group: AI Core Infra
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Vérifiez que GitLab Duo est configuré et fonctionne correctement sur GitLab Dedicated for Government.
title: Configurer GitLab Duo sur GitLab Dedicated for Government
gitlab_dedicated: yes
---

{{< details >}}

- Offre : GitLab Dedicated for Government

{{< /details >}}

Pour GitLab Dedicated for Government, vous devez utiliser l'architecture GitLab Duo Self-Hosted. La passerelle d'IA et les modèles gérés par GitLab ne sont pas disponibles.

> [!note]
> Les fonctionnalités de la plateforme GitLab Duo Agent sont autorisées à être utilisées dans GitLab Dedicated for Government sur la base de chaque fonctionnalité. Pour plus d'informations, consultez [GitLab Dedicated for Government](../../../subscriptions/gitlab_dedicated_for_government/_index.md#gitlab-duo).

Pour configurer GitLab Duo Self-Hosted :

1. Vérifiez que [le mode silencieux est désactivé](../../silent_mode/_index.md#turn-off-silent-mode).
1. [Installez la passerelle d'IA GitLab](../../../install/install_ai_gateway.md) dans votre AWS GovCloud (US-West). Pour des performances optimales, [co-localisez votre passerelle d'IA et votre instance](../../../install/install_ai_gateway.md#co-locate-your-ai-gateway-and-instance).
   - Utilisez une [image de passerelle d'IA validée FIPS](../../../install/install_ai_gateway.md#fips-validated-images). Les images validées FIPS sont publiées dans le [registre de conteneurs](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/container_registry/9518478?orderBy=PUBLISHED_AT&sort=desc&search%5B%5D=self-hosted). Sélectionnez la dernière image taguée avec la même version de GitLab que celle exécutée par votre instance.
   - Vous pouvez déployer la passerelle d'IA en utilisant [Docker](../../../install/install_ai_gateway.md#install-by-using-docker) ou le [chart Helm GitLab](../../../install/install_ai_gateway.md#install-by-using-helm-chart). Pour plus d'informations sur chaque méthode de déploiement, consultez [les mises à jour de sécurité et la vérification des images](../../../install/install_ai_gateway.md#security-updates-and-image-verification).
1. Dans l'environnement où vous avez installé la passerelle d'IA, [configurez vos paramètres réseau](../../../install/install_ai_gateway.md#restrict-network-access) pour activer l'accès à votre instance et aux LLM sélectionnés.
1. [Configurez l'accès à la passerelle d'IA locale](../../gitlab_duo_self_hosted/configure_duo_features.md#configure-access-to-the-local-ai-gateway).
1. [Ajoutez un modèle auto-hébergé](../../gitlab_duo_self_hosted/configure_duo_features.md#add-a-self-hosted-model) à utiliser avec les fonctionnalités de GitLab Duo.
1. Demandez à GitLab d'activer la connectivité réseau de votre instance vers votre passerelle d'IA auto-hébergée et les LLM sélectionnés en [créant un ticket d'assistance](https://support.gitlab.com/hc/en-us/requests/new?ticket_form_id=4414917877650).
1. [Consultez les tendances GitLab Duo et SDLC](../../../user/analytics/duo_and_sdlc_trends.md#view-gitlab-duo-and-sdlc-trends) pour mesurer l'impact de GitLab Duo sur la productivité de votre équipe.

## Sujets connexes {#related-topics}

- [Modèles pris en charge et configuration matérielle requise](../../gitlab_duo_self_hosted/supported_models_and_hardware_requirements.md)
- [Dépannage de GitLab Duo Self-Hosted](../../gitlab_duo_self_hosted/troubleshooting.md)
- [Exécuter un contrôle de santé pour GitLab Duo](_index.md#run-a-health-check-for-gitlab-duo)
