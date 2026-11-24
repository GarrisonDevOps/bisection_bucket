# frozen_string_literal: true

module Mutations
  module Ai
    module DuoSettings
      class SetDuoAvailability < BaseMutation
        graphql_name 'AdminSetDuoAvailability'
        description 'Sets an admin-locked GitLab Duo availability override on a group.'

        authorize :lock_namespace_duo_feature
        authorize_granular_token permissions: :lock_namespace_duo_feature,
          boundary_argument: :group_id, boundary_type: :group

        argument :group_id, ::Types::GlobalIDType[::Group],
          required: true,
          description: 'Group to set the GitLab Duo availability override on.'

        argument :availability, ::Types::Ai::DuoSettings::DuoAvailabilityEnum,
          required: true,
          description: 'GitLab Duo availability state to lock on the group.'

        argument :clear_descendants, GraphQL::Types::Boolean,
          required: false,
          default_value: false,
          description: 'Clear conflicting admin-locked overrides on descendant groups instead of rejecting.'

        field :availability, ::Types::Ai::DuoSettings::DuoAvailabilityEnum,
          null: true,
          description: 'Resolved GitLab Duo availability for the group after the mutation.'

        field :admin_locked, GraphQL::Types::Boolean,
          null: true,
          description: 'Whether the group has an admin-locked GitLab Duo availability override.'

        field :conflicting_ancestor, ::Types::Ai::DuoSettings::DuoAvailabilityLockedAncestorType,
          null: true,
          description: 'Ancestor group whose admin lock blocked the mutation, if any. ' \
            'When present, the override was not applied.'

        field :affected_admin_locked_descendants,
          ::Types::Ai::DuoSettings::DuoAvailabilityLockedAncestorType.connection_type,
          null: true,
          description: 'Descendant groups with admin-locked overrides that must be cleared before this override ' \
            'can be applied. Present only when `clearDescendants` was false; the override was not applied.'

        def resolve(group_id:, availability:, clear_descendants: false)
          group = authorized_find!(id: group_id)

          result = ::Ai::DuoSettings::SetNamespaceOverrideService.new(
            namespace: group,
            current_user: current_user,
            availability: availability,
            clear_descendants: clear_descendants
          ).execute

          return success_payload(result) if result.success?

          conflict_payload(result)
        end

        private

        def success_payload(result)
          namespace_setting = result.payload[:namespace_setting]

          {
            availability: namespace_setting.duo_availability.to_s,
            admin_locked: namespace_setting.admin_locked_duo_features_enabled,
            conflicting_ancestor: nil,
            affected_admin_locked_descendants: [],
            errors: []
          }
        end

        # Translate the service's typed conflict reasons into the typed GraphQL
        # fields the frontend reads, instead of generic error strings.
        def conflict_payload(result)
          namespaces = Array(result.payload && result.payload[:namespaces])

          case result.reason
          when :parent_admin_locked
            { availability: nil, admin_locked: nil, conflicting_ancestor: namespaces.first, errors: [result.message] }
          when :descendant_admin_locked
            {
              availability: nil,
              admin_locked: nil,
              affected_admin_locked_descendants: namespaces,
              errors: [result.message]
            }
          else
            { availability: nil, admin_locked: nil, errors: [result.message] }
          end
        end
      end
    end
  end
end
