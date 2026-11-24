# frozen_string_literal: true

module Types
  module Security
    module Ascp
      # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled by parent resolver
      class ComponentType < BaseObject
        graphql_name 'AscpComponent'
        description 'A logical component of a project identified by ASCP security scanning'

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :id, ::Types::GlobalIDType[::Security::Ascp::Component],
          null: false,
          description: 'Global ID of the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :title, GraphQL::Types::String,
          null: false,
          description: 'Title of the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :description, GraphQL::Types::String,
          null: true,
          description: 'Description of the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :sub_directory, GraphQL::Types::String,
          null: false,
          description: 'Sub-directory containing the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :expected_user_behavior, GraphQL::Types::String,
          null: true,
          description: 'Expected user behavior for the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :scan, Types::Security::Ascp::ScanType,
          null: false,
          description: 'Scan when the component was identified.',
          scopes: [:api, :read_api, :ai_workflows]

        field :security_context, Types::Security::Ascp::SecurityContextType,
          null: true,
          description: 'Security context for the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :dependencies, Types::Security::Ascp::ComponentType.connection_type,
          null: false,
          description: 'Components the component depends on.',
          method: :dependency_components,
          scopes: [:api, :read_api, :ai_workflows]

        field :created_at, Types::TimeType,
          null: false,
          description: 'Timestamp when the component was created.',
          scopes: [:api, :read_api, :ai_workflows]

        field :updated_at, Types::TimeType,
          null: false,
          description: 'Timestamp when the component was last updated.',
          scopes: [:api, :read_api, :ai_workflows]

        def scan
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Security::Ascp::Scan, object.scan_id).find
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
