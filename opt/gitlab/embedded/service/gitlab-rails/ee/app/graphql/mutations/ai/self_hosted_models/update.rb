# frozen_string_literal: true

module Mutations
  module Ai
    module SelfHostedModels
      class Update < Base
        graphql_name 'AiSelfHostedModelUpdate'
        description "Updates a self-hosted model."

        field_self_hosted_model

        argument :id,
          ::Types::GlobalIDType[::Ai::SelfHostedModel],
          required: true,
          description: 'Global ID of the self-hosted model to update.'

        arguments_for_model_attributes

        authorize_granular_token permissions: :update_ai_self_hosted_model,
          boundary: :instance, boundary_type: :instance

        def resolve(**args)
          check_feature_access!

          model = find_object(id: args.delete(:id))

          result = ::Ai::SelfHostedModels::UpdateService.new(model, current_user, args).execute

          {
            self_hosted_model: result.success? ? result.payload : nil,
            errors: result.error? ? Array.wrap(result.errors) : []
          }
        end

        private

        def find_object(id:)
          GitlabSchema.object_from_id(id, expected_type: ::Ai::SelfHostedModel).sync
        end
      end
    end
  end
end
