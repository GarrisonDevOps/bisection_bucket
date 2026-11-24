# frozen_string_literal: true

module Mutations
  module Ai
    module SelfHostedModels
      class ConnectionCheck < Base
        graphql_name 'AiSelfHostedModelConnectionCheck'

        field :result,
          ::Types::CloudConnector::ProbeResultType,
          null: true,
          description: 'Self-hosted hosted connection check result.'

        description 'Checks if the AI Gateway can establish a connection with the given model configuration.'

        arguments_for_model_attributes

        authorize_granular_token permissions: :check_ai_self_hosted_model_connection,
          boundary: :instance, boundary_type: :instance

        def resolve(**args)
          check_feature_access!

          model = build_model(args)
          result = execute_probe(model)

          {
            result: result,
            errors: []
          }
        end

        private

        def build_model(params)
          ::Ai::SelfHostedModel.new(params)
        end

        def execute_probe(model)
          ::CloudConnector::StatusChecks::Probes::SelfHosted::ModelConfigurationProbe.new(current_user, model).execute
        end
      end
    end
  end
end
