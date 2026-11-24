# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- authorization is handled on the group/project field and in the finder
    class DependencyFirewallPackageVersionEntryType < BaseObject
      graphql_name 'DependencyFirewallPackageVersionEntry'
      description 'A package version denied by a dependency firewall `package_version` rule.'
      authorize_granular_token skip_reason: :parent_authorizes

      field :name, GraphQL::Types::String, null: false,
        description: 'Exact package name the entry matches.'
      field :reason, GraphQL::Types::String, null: true,
        description: 'Reason shown to developers when the version is denied.'
      field :reference_link, GraphQL::Types::String, null: true,
        description: 'Link to more information about the entry. Shown in the UI only.'
      field :version, GraphQL::Types::String, null: false,
        description: 'Exact package version the entry matches.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
