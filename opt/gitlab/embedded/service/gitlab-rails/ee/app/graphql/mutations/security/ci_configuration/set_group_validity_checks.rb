# frozen_string_literal: true

module Mutations
  module Security
    module CiConfiguration
      class SetGroupValidityChecks < BaseMutation
        graphql_name 'SetGroupValidityChecks'

        include Mutations::ResolvesGroup

        description 'Enable or disable Validity Checks for a group.'

        argument :validity_checks_enabled, GraphQL::Types::Boolean, required: true,
          description: 'Whether to enable validity checks for all projects in the group.'

        argument :namespace_path, GraphQL::Types::ID,
          required: true,
          description: 'Full path of the group.'

        argument :projects_to_exclude, [GraphQL::Types::Int], required: false,
          description: 'IDs of projects to exclude from validity checks configuration.'

        field :validity_checks_enabled, GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether validity checks have been enabled for the group.'

        field :errors, [GraphQL::Types::String],
          null: false,
          description: 'Errors encountered during the mutation.'

        authorize :update_secret_detection_validity_check

        authorize_granular_token permissions: :update_security_setting,
          boundary_argument: :namespace_path, boundary_type: :group

        def resolve(namespace_path:, validity_checks_enabled:, projects_to_exclude: [])
          group = authorized_find!(group_path: namespace_path)

          raise_resource_not_available_error! 'Setting only available for group namespaces.' unless group.is_a? Group

          ::Security::Configuration::SetGroupValidityChecksWorker.perform_async(group.id, validity_checks_enabled, current_user.id, projects_to_exclude) # rubocop:disable CodeReuse/Worker -- This is meant to be a background job

          {
            validity_checks_enabled: validity_checks_enabled,
            errors: []
          }
        end

        private

        def find_object(group_path:)
          resolve_group(full_path: group_path)
        end
      end
    end
  end
end
