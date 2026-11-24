# frozen_string_literal: true

module Mutations
  module Ai
    module SelfHostedModels
      class Delete < Base
        graphql_name 'AiSelfHostedModelDelete'
        description "Deletes a self-hosted model."

        argument :id,
          ::Types::GlobalIDType[::Ai::SelfHostedModel],
          required: true,
          description: 'Global ID of the self-hosted model to delete.'

        authorize_granular_token permissions: :delete_ai_self_hosted_model,
          boundary: :instance, boundary_type: :instance

        def resolve(**args)
          check_feature_access!

          model = find_object(id: args[:id])

          return { errors: ["Self-hosted model not found"] } unless model

          result = ::Ai::SelfHostedModels::DestroyService.new(model, current_user).execute

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
