# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- reached only through the authorized rule activity field
    class DependencyFirewallRuleLastModifiedType < BaseObject
      graphql_name 'DependencyFirewallRuleLastModified'
      description 'When and by whom a dependency firewall policy was last modified.'
      authorize_granular_token parent_authorizes: :read_security_policy

      field :at, ::Types::TimeType, null: true,
        description: 'Timestamp of when the policy was last modified.'
      field :by, ::Types::UserType, null: true,
        description: 'User who last modified the policy.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
