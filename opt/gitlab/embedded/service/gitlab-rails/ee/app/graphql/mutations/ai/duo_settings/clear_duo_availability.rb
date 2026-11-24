# frozen_string_literal: true

module Mutations
  module Ai
    module DuoSettings
      class ClearDuoAvailability < BaseMutation
        graphql_name 'AdminClearDuoAvailability'
        description 'Clears an admin-locked GitLab Duo availability override from a group.'

        authorize :lock_namespace_duo_feature
        authorize_granular_token permissions: :lock_namespace_duo_feature,
          boundary_argument: :group_id, boundary_type: :group

        argument :group_id, ::Types::GlobalIDType[::Group],
          required: true,
          description: 'Group to clear the GitLab Duo availability override from.'

        field :availability, ::Types::Ai::DuoSettings::DuoAvailabilityEnum,
          null: true,
          description: 'Resolved GitLab Duo availability for the group after the override is cleared.'

        field :admin_locked, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether the group has an admin-locked GitLab Duo availability override.'

        def resolve(group_id:)
          group = authorized_find!(id: group_id)

          result = ::Ai::DuoSettings::ClearNamespaceOverrideService.new(
            namespace: group,
            current_user: current_user
          ).execute

          return { availability: nil, admin_locked: nil, errors: [result.message] } if result.error?

          namespace_setting = result.payload[:namespace_setting]

          {
            availability: namespace_setting.duo_availability.to_s,
            admin_locked: namespace_setting.admin_locked_duo_features_enabled,
            errors: []
          }
        end
      end
    end
  end
end
