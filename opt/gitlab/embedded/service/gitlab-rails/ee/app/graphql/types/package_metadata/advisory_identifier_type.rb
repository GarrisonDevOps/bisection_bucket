# frozen_string_literal: true

module Types
  # rubocop: disable Gitlab/BoundedContexts -- this namespace is already established, embedding it deeper into another namespace would make things inconsistent.
  module PackageMetadata
    # rubocop: disable Graphql/AuthorizeTypes -- authorization will be handled by the parent type
    class AdvisoryIdentifierType < BaseObject
      graphql_name 'PackageMetadataAdvisoryIdentifier'
      description 'Represents an identifier for a package metadata advisory.'

      authorize_granular_token parent_authorizes: :read_metadata

      field :type, GraphQL::Types::String,
        null: false,
        description: 'Type of identifier (for example, CVE, CWE, OSVDB, USN).'

      field :name, GraphQL::Types::String,
        null: false,
        description: 'Human-readable name of the identifier.'

      field :value, GraphQL::Types::String,
        null: false,
        description: 'Value of the identifier, for matching purposes.'

      field :url, GraphQL::Types::String,
        null: true,
        description: "URL of the identifier's documentation."
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
  # rubocop: enable Gitlab/BoundedContexts
end
