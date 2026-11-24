# frozen_string_literal: true

module Types
  module Security
    module Ascp
      # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled by parent resolver
      class SecurityContextType < BaseObject
        graphql_name 'AscpSecurityContext'
        description 'Security context for an ASCP component'

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :id, ::Types::GlobalIDType[::Security::Ascp::SecurityContext],
          null: false,
          description: 'ID of the security context.',
          scopes: [:api, :read_api, :ai_workflows]

        field :summary, GraphQL::Types::String,
          null: true,
          description: 'High-level threat model summary.',
          scopes: [:api, :read_api, :ai_workflows]

        field :authentication_model, GraphQL::Types::String,
          null: true,
          description: 'How users authenticate to the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :authorization_model, GraphQL::Types::String,
          null: true,
          description: 'How access is controlled for the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :data_sensitivity, GraphQL::Types::String,
          null: true,
          description: 'Types of sensitive data handled by the component.',
          scopes: [:api, :read_api, :ai_workflows]

        field :scan, Types::Security::Ascp::ScanType,
          null: false,
          description: 'Scan when the security context was generated.',
          scopes: [:api, :read_api, :ai_workflows]

        field :security_guidelines, Types::Security::Ascp::SecurityGuidelineType.connection_type,
          null: false,
          description: 'Security guidelines for the context.',
          method: :guidelines,
          scopes: [:api, :read_api, :ai_workflows]

        # rubocop:disable GraphQL/ExtractType -- prefix match is coincidental; this is a standalone enum list
        field :security_boundary, [Types::Security::Ascp::SecurityBoundaryEnum],
          null: false,
          description: 'Security boundaries the component sits on.',
          scopes: [:api, :read_api, :ai_workflows]
        # rubocop:enable GraphQL/ExtractType

        def scan
          ::Gitlab::Graphql::Loaders::BatchModelLoader.new(::Security::Ascp::Scan, object.scan_id).find
        end
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
