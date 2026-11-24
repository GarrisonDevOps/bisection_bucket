# frozen_string_literal: true

module Types
  module Cd
    class ApplicationFlowDefinitionType < ::Types::BaseObject
      graphql_name 'CdApplicationFlowDefinition'
      description 'Continuous deployment application flow definition.'

      connection_type_class Types::CountableConnectionType

      authorize :read_cd_application_flow_definition
      authorize_granular_token permissions: :read_cd_application_flow_definition,
        boundaries: [
          { boundary: :instance, boundary_type: :instance }
        ]

      field :id, Types::GlobalIDType[::Cd::ApplicationFlowDefinition],
        null: false,
        description: 'Global ID of the application flow definition.'

      field :version, GraphQL::Types::Int,
        null: false,
        description: 'Version of the application flow definition.'

      field :definition, GraphQL::Types::String,
        null: true,
        description: 'Body of the application flow definition.',
        complexity: 5,
        experiment: { milestone: '19.2' }

      field :application, ::Types::Cd::ApplicationType,
        null: true,
        description: 'Application the flow definition belongs to.'

      # Plain list, not a connection, and computed rather than persisted: mirrors
      # CdRollout#rolloutSteps, but there is no Cd::RolloutStep row behind it (see
      # Cd::ApplicationFlowDefinitions::DefinitionSteps::Builder).
      field :definition_steps, [::Types::Cd::DefinitionStepType],
        null: true,
        description: 'Top-level nodes of the flow definition\'s static step tree, computed from its YAML ' \
          'and not persisted. A stage node exposes its nested steps through its own `steps` field.',
        resolver: ::Resolvers::Cd::DefinitionStepsResolver,
        experiment: { milestone: '19.3' }

      field :created_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the application flow definition was created.'

      field :updated_at, Types::TimeType,
        null: false,
        description: 'Timestamp of when the application flow definition was last updated.'

      def application
        ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Cd::Application, object.application_id).find
      end
    end
  end
end
