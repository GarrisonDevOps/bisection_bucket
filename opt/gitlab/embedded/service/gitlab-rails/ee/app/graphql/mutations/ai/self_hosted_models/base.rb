# frozen_string_literal: true

module Mutations
  module Ai
    module SelfHostedModels
      # rubocop: disable GraphQL/GraphqlName -- It's an abstraction not meant to be used in the schema
      class Base < BaseMutation
        def self.field_self_hosted_model
          field :self_hosted_model,
            Types::Ai::SelfHostedModels::SelfHostedModelType,
            null: true,
            description: 'Self-hosted model after mutation.'
        end

        def self.arguments_for_model_attributes
          argument :name, GraphQL::Types::String,
            required: true,
            description: 'Deployment name of the self-hosted model.'

          argument :model, ::Types::Ai::SelfHostedModels::AcceptedModelsEnum,
            required: true,
            description: 'AI model deployed.'

          argument :endpoint, GraphQL::Types::String,
            required: false,
            description: 'Endpoint of the self-hosted model.'

          argument :api_token, GraphQL::Types::String,
            required: false,
            description: 'API token to access the self-hosted model, if any.'

          argument :identifier, GraphQL::Types::String,
            required: false,
            description: 'Identifier for 3rd party model provider.'

          argument :iam_role, GraphQL::Types::String,
            required: false,
            description: 'IAM role ARN that the AI Gateway assumes through STS AssumeRole ' \
              'when calling Amazon Bedrock. Only used by the Amazon Bedrock provider.'

          argument :provider, ::Types::Ai::SelfHostedModels::ProviderEnum,
            required: true,
            description: 'Provider for the self-hosted model.'
        end

        private

        def check_feature_access!
          raise_resource_not_available_error! unless Ability.allowed?(current_user, :manage_self_hosted_models_settings)
        end
      end
      # rubocop: enable GraphQL/GraphqlName
    end
  end
end
