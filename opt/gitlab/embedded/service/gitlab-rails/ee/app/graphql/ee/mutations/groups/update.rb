# frozen_string_literal: true

module EE
  module Mutations
    module Groups
      module Update
        extend ActiveSupport::Concern

        prepended do
          argument :duo_features_enabled, GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :duo_features_enabled),
            experiment: { milestone: '16.10' }
          argument :lock_duo_features_enabled, GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :lock_duo_features_enabled),
            experiment: { milestone: '16.10' }
          argument :web_based_commit_signing_enabled,
            GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :web_based_commit_signing_enabled),
            experiment: { milestone: '18.2' }
          argument :ai_audit_events_storage_enabled,
            GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :ai_audit_events_storage_enabled),
            experiment: { milestone: '19.2' }
          argument :lock_ai_audit_events_storage_enabled, GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :lock_ai_audit_events_storage_enabled),
            experiment: { milestone: '19.2' }
          argument :tool_approval_for_session_enabled, GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :tool_approval_for_session_enabled),
            experiment: { milestone: '18.11' }
          argument :lock_tool_approval_for_session_enabled, GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :lock_tool_approval_for_session_enabled),
            experiment: { milestone: '18.11' }
          argument :duo_auto_mode_enabled, GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :duo_auto_mode_enabled),
            experiment: { milestone: '19.5' }
          argument :lock_duo_auto_mode_enabled, GraphQL::Types::Boolean,
            required: false,
            description: copy_field_description(::Types::GroupType, :lock_duo_auto_mode_enabled),
            experiment: { milestone: '19.5' }
          argument :built_in_project_templates_enabled, GraphQL::Types::Boolean,
            required: false,
            description: 'Indicates whether built-in project templates are available for new projects in the group.',
            experiment: { milestone: '19.0' }
          argument :lock_built_in_project_templates_enabled, GraphQL::Types::Boolean,
            required: false,
            description: 'Indicates if the built-in project templates enabled setting is enforced for all subgroups.',
            experiment: { milestone: '19.0' }
        end
      end
    end
  end
end
