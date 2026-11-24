# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- authorization is handled on the parent field
    class DependencyFirewallSeverityCountType < BaseObject
      graphql_name 'DependencyFirewallSeverityCount'
      description 'Count of distinct prevented packages at one severity level.'
      authorize_granular_token skip_reason: :parent_authorizes

      field :count, GraphQL::Types::Int, null: false,
        description: 'Number of distinct packages whose highest carried severity matches the severity field.'
      field :severity, Types::VulnerabilitySeverityEnum, null: false,
        description: 'Severity level of the count.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
