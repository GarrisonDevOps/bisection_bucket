# frozen_string_literal: true

module Types
  module Security
    module Ascp
      # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled by parent resolver
      class ScanType < BaseObject
        graphql_name 'AscpScan'
        description 'An ASCP scan of a project'

        def self.authorization_scopes
          super + [:ai_workflows]
        end

        field :id, ::Types::GlobalIDType[::Security::Ascp::Scan],
          null: false,
          description: 'ID of the scan.',
          scopes: [:api, :read_api, :ai_workflows]

        field :scan_sequence, GraphQL::Types::Int,
          null: false,
          description: 'Sequence number of the scan within the project.',
          scopes: [:api, :read_api, :ai_workflows]

        field :commit_sha, GraphQL::Types::String,
          null: false,
          description: 'Git commit SHA that was scanned.',
          scopes: [:api, :read_api, :ai_workflows]

        # rubocop: disable GraphQL/ExtractType -- scan_type is a core attribute, not suitable for extraction
        field :scan_type, Types::Security::Ascp::ScanTypeEnum,
          null: false,
          description: 'Type of scan (full or incremental).',
          scopes: [:api, :read_api, :ai_workflows]
        # rubocop: enable GraphQL/ExtractType

        field :base_commit_sha, GraphQL::Types::String,
          null: true,
          description: 'Base commit SHA for incremental scans.',
          scopes: [:api, :read_api, :ai_workflows]

        # rubocop: disable GraphQL/ExtractType -- base_scan is a self-reference, not suitable for extraction
        field :base_scan, Types::Security::Ascp::ScanType,
          null: true,
          description: 'Reference to the base scan for incremental scans.',
          scopes: [:api, :read_api, :ai_workflows]
        # rubocop: enable GraphQL/ExtractType

        field :created_at, Types::TimeType,
          null: false,
          description: 'Timestamp when the scan was created.',
          scopes: [:api, :read_api, :ai_workflows]

        field :updated_at, Types::TimeType,
          null: false,
          description: 'Timestamp when the scan was last updated.',
          scopes: [:api, :read_api, :ai_workflows]
      end
      # rubocop: enable Graphql/AuthorizeTypes
    end
  end
end
