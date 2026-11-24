---
stage: GitLab Dedicated
group: AI Model Services
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "Hébergez vos propres modèles d'IA pour GitLab Dedicated."
title: Configurer des modèles auto-hébergés pour GitLab Dedicated
---

{{< details >}}

- Édition : GitLab Ultimate
- Offre : GitLab Dedicated

{{< /details >}}

Utilisez la passerelle d'IA pour GitLab Dedicated afin de connecter vos modèles auto-hébergés. Avec la plateforme d'agents GitLab Duo, vous pouvez connecter la passerelle d'IA à Amazon Bedrock pour maintenir l'inférence dans votre région AWS. Vous pouvez également utiliser le fournisseur de votre choix.

## Configuration hybride de la passerelle d'IA et des modèles {#hybrid-ai-gateway-and-model-configuration}

La passerelle d'IA pour GitLab Dedicated s'exécute dans le même environnement et la même région AWS que votre instance GitLab Dedicated. GitLab héberge et configure la passerelle pour vous. Vous n'avez pas besoin d'installer une passerelle d'IA ni de saisir une URL de passerelle d'IA locale dans la zone **Admin**.

Avec la passerelle d'IA pour GitLab Dedicated, votre instance utilise une [configuration hybride de la passerelle d'IA et des modèles](../../gitlab_duo_self_hosted/_index.md#hybrid-ai-gateway-and-model-configuration). Pour chaque fonctionnalité GitLab Duo, vous pouvez utiliser l'une ou l'autre des options suivantes :

- Modèle auto-hébergé : la fonctionnalité envoie des requêtes via la passerelle d'IA pour GitLab Dedicated vers le point de terminaison du modèle que vous configurez.
- Modèle géré par GitLab : la fonctionnalité envoie des requêtes à la passerelle d'IA de GitLab.com. La passerelle d'IA pour GitLab Dedicated ne peut pas router vers les modèles gérés par GitLab.

La passerelle d'IA pour GitLab Dedicated ne modifie pas le comportement par défaut de votre instance. Par défaut, toutes les fonctionnalités GitLab Duo utilisent des modèles gérés par GitLab via la passerelle d'IA de GitLab.com. Votre instance envoie des requêtes via la passerelle d'IA pour GitLab Dedicated uniquement pour les fonctionnalités que vous configurez pour utiliser un modèle auto-hébergé.

## Ajouter un modèle auto-hébergé {#add-a-self-hosted-model}

Vous pouvez ajouter un modèle auto-hébergé à utiliser sur votre instance GitLab.

Pour ajouter un modèle auto-hébergé :

1. Dans le coin supérieur droit, sélectionnez **Admin**.
1. Dans la barre latérale gauche, sélectionnez **GitLab Duo**.
1. Sélectionnez **Gérer les modèles**.
1. Sélectionnez **Ajouter un modèle auto-hébergé**.
1. Remplissez les champs :
   - **Nom de déploiement** : saisissez un nom pour identifier de manière unique le déploiement du modèle (par exemple, `Mixtral-8x7B-it-v0.1 on GCP`).
   - **Famille de modèles** : sélectionnez la famille de modèles à laquelle appartient le déploiement. Vous pouvez sélectionner un modèle pris en charge ou compatible.
   - **Point de terminaison** : saisissez l'URL où le modèle est hébergé.
   - **Clé de l'API** : Facultatif. Ajoutez une clé d'API pour accéder au modèle.
   - **Identifiant du modèle** : saisissez l'ID du modèle en fonction de votre méthode de déploiement. L'ID du modèle doit correspondre au format suivant :

     | Méthode de déploiement | Format | Exemple |
     |-------------------|--------|---------|
     | Amazon Bedrock (ID du modèle) | `bedrock/<model ID>` | `bedrock/mistral.mixtral-8x7b-instruct-v0:1` |
     | Amazon Bedrock (ARN du profil d'inférence d'application) | `bedrock/converse/<application inference profile ARN>` | `bedrock/converse/arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abcd1234efgh` |
     | Gemini Enterprise Agent Platform | `vertex_ai/<model ID>` | `vertex_ai/claude-sonnet-4-6@default` |
     | Anthropic                                                            | `anthropic/<model ID>`                     | `anthropic/claude-opus-4-6` |
     | OpenAI                                                              | `openai/<model ID>`                        | `openai/gpt-5` |
     | Azure OpenAI                                                          | `azure/<model ID>`                         | `azure/gpt-35-turbo` |

1. Sélectionnez **Ajouter un modèle auto-hébergé**.

L'ajout d'un modèle auto-hébergé le rend disponible à l'utilisation, mais ne l'attribue à aucune fonctionnalité GitLab Duo. Pour l'utiliser, vous devez [sélectionner un modèle auto-hébergé pour la fonctionnalité](../../gitlab_duo_self_hosted/configure_duo_features.md#select-a-self-hosted-model-for-a-feature). Les fonctionnalités pour lesquelles vous ne sélectionnez pas de modèle auto-hébergé continuent d'utiliser des modèles gérés par GitLab via la passerelle d'IA de GitLab.com.
