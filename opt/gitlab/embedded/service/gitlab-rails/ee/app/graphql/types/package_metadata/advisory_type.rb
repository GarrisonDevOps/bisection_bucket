# frozen_string_literal: true

module Types
  # rubocop: disable Gitlab/BoundedContexts -- this namespace is already established, embedding it deeper into another namespace would make things inconsistent.
  module PackageMetadata
    # rubocop: disable Graphql/AuthorizeTypes -- authorization will be handled in the resolver
    class AdvisoryType < BaseObject
      graphql_name 'PackageMetadataAdvisory'
      description 'Represents a security advisory from package metadata sources.'

      authorize_granular_token permissions: :read_metadata, boundary: :instance, boundary_type: :instance

      field :advisory_xid, GraphQL::Types::String, null: false, description: 'External ID of the advisory.'
      field :created_at, Types::TimeType, null: false, description: 'Timestamp when the advisory was created.'
      field :cve, GraphQL::Types::String, null: true, description: 'CVE identifier if applicable.'
      # rubocop: disable GraphQL/ExtractType -- cvss_v2 and cvss_v3 are separate columns in the database
      field :cvss_v2, GraphQL::Types::String, null: true, description: 'CVSS v2 vector string.'
      field :cvss_v3, GraphQL::Types::String, null: true, description: 'CVSS v3 vector string.'
      # rubocop: enable GraphQL/ExtractType
      field :description, GraphQL::Types::String, null: true, description: 'Description of the advisory.'
      field :id, GraphQL::Types::ID, null: false, description: 'ID of the advisory.'
      field :identifiers, [Types::PackageMetadata::AdvisoryIdentifierType],
        null: false,
        description: 'Additional identifiers for the advisory.'
      field :published_date, Types::DateType, null: false, description: 'Date when the advisory was published.'
      field :source_xid, Types::PackageMetadata::AdvisorySourceEnum, null: false, description: 'Source of the advisory.'
      field :title, GraphQL::Types::String, null: true, description: 'Title of the advisory.'
      field :updated_at, Types::TimeType, null: false, description: 'Timestamp when the advisory was last updated.'
      field :urls, [GraphQL::Types::String], null: true, description: 'Related URLs for the advisory.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
  # rubocop: enable Gitlab/BoundedContexts
end
