# frozen_string_literal: true

module Mutations
  module Cd
    module Rollouts
      class Create < ::Mutations::BaseMutation
        graphql_name 'CdRolloutCreate'
        description 'Creates a continuous deployment rollout in an organization.'

        authorize :create_cd_rollout
        authorize_granular_token permissions: :create_cd_rollout,
          boundary: :instance,
          boundary_type: :instance

        argument :organization_id, ::Types::GlobalIDType[::Organizations::Organization],
          required: true,
          description: 'Global ID of the organization to create the rollout in.'

        argument :version_set_id, ::Types::GlobalIDType[::Cd::VersionSet],
          required: true,
          description: 'Global ID of the version set the rollout deploys.'

        field :rollout, ::Types::Cd::RolloutType,
          null: true,
          description: 'Rollout created by the mutation.'

        def ready?(**args)
          raise_resource_not_available_error! unless Feature.enabled?(:ai_native_deploy, current_user)

          super
        end

        def resolve(args)
          organization = authorized_find!(organization_id: args[:organization_id])

          params = {
            version_set: resolve_gid(args[:version_set_id], ::Cd::VersionSet)
          }

          response = ::Cd::Rollouts::CreateService
            .new(parent: organization, current_user: current_user, params: params)
            .execute

          {
            rollout: response.success? ? response.payload[:rollout] : nil,
            errors: response.errors
          }
        end

        private

        def find_object(organization_id:)
          ::GitlabSchema.object_from_id(organization_id, expected_type: ::Organizations::Organization).sync
        end

        def resolve_gid(global_id, expected_type)
          ::GitlabSchema.object_from_id(global_id, expected_type: expected_type).sync
        end
      end
    end
  end
end
