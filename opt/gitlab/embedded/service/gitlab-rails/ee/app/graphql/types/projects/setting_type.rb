# frozen_string_literal: true

module Types
  module Projects
    # rubocop: disable Graphql/AuthorizeTypes -- parent handles auth
    class SettingType < BaseObject
      graphql_name 'ProjectSetting'

      authorize_granular_token parent_authorizes: :read_project

      field :duo_features_enabled,
        GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether GitLab Duo features are enabled for the project.'

      field :tool_approval_for_session_enabled,
        GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether tool approval for Duo Workflow sessions is enabled for the project.'

      field :duo_auto_mode_enabled,
        GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether Duo Agent Platform auto mode is enabled for the project.'

      field :duo_context_exclusion_settings, # rubocop:disable GraphQL/ExtractType -- can't move existing field
        Types::Projects::DuoContextExclusionSettingsType,
        null: true,
        description: 'Settings for excluding files from Duo context.'

      field :project,
        Types::ProjectType,
        null: true,
        description: 'Project the settings belong to.'

      field :web_based_commit_signing_enabled,
        GraphQL::Types::Boolean,
        null: false,
        description: 'Indicates whether web-based commit signing is enabled for the project.',
        experiment: { milestone: '18.2' }

      field :ai_audit_events_storage_enabled,
        GraphQL::Types::Boolean,
        null: true,
        description: 'Indicates whether AI audit events are stored for the project.',
        experiment: { milestone: '19.2' }
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
