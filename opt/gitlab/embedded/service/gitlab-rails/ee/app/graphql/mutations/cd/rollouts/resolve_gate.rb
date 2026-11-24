# frozen_string_literal: true

module Mutations
  module Cd
    module Rollouts
      class ResolveGate < ::Mutations::BaseMutation
        graphql_name 'CdRolloutGateResolve'
        description 'Resolves an open approval gate on a continuous deployment rollout by ' \
          'recording the decision in the rollout transition journal.'

        authorize :resolve_cd_rollout_gate
        authorize_granular_token permissions: :resolve_cd_rollout_gate,
          boundary: :instance,
          boundary_type: :instance

        argument :id, ::Types::GlobalIDType[::Cd::Rollout],
          required: true,
          description: 'Global ID of the rollout whose approval gate is being resolved.'

        argument :status, ::Types::Cd::RolloutGateStatusEnum,
          required: true,
          description: 'Decision to record for the approval gate.'

        argument :resolution_reason, GraphQL::Types::String,
          required: false,
          description: 'Reason for the decision.'

        field :rollout_transition, ::Types::Cd::RolloutTransitionType,
          null: true,
          description: 'Rollout transition journal entry created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          rollout = authorized_find!(id: args[:id])

          response = ::Cd::Rollouts::ResolveGateService
            .new(rollout, current_user: current_user, status: args[:status],
              resolution_reason: args[:resolution_reason])
            .execute

          {
            rollout_transition: response.success? ? response.payload[:rollout_transition] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(id:)
          ::GitlabSchema.object_from_id(id, expected_type: ::Cd::Rollout).sync
        end
      end
    end
  end
end
