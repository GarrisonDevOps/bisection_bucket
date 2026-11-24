# frozen_string_literal: true

module Types
  module Ai
    module DuoWorkflows
      class EnablementType < Types::BaseObject # rubocop:disable Graphql/AuthorizeTypes -- parent is already authorized
        graphql_name 'DuoWorkflowEnablement'
        description 'Duo Agent Platform enablement status checks.'

        authorize_granular_token parent_authorizes: :read_project

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :create_duo_workflow_for_ci_allowed, GraphQL::Types::Boolean,
          null: false,
          experiment: { milestone: '18.9' },
          description: 'Indicates whether the user can create Duo Workflows for CI in the project.'
        field :enabled, GraphQL::Types::Boolean,
          null: false,
          description: 'Indicates whether Duo Agent Platform is enabled for current user and the project.'

        field :checks, [::Types::Ai::DuoWorkflows::EnablementCheckType],
          null: true,
          description: 'Enablement checks.'
        field :enabled_foundational_flows, [GraphQL::Types::String],
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'References of the foundational flows enabled for the project, for example "code_review/v1".'
        field :foundational_flows_enabled, GraphQL::Types::Boolean,
          null: true,
          scopes: [:api, :read_api, :ai_workflows],
          description: 'Indicates if Duo Agent Platform foundational flows are enabled for the project.'
        field :remote_flows_enabled, GraphQL::Types::Boolean,
          null: true,
          description: 'Indicates if Duo Agent Platform remote flows are enabled for the project.'
      end
    end
  end
end
