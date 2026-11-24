# frozen_string_literal: true

module Types
  module Security
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled in the resolver
    # this represents a hash, from the orchestration policy configuration
    # the authorization happens for that configuration
    class DependencyFirewallPolicyAttributesType < BaseObject
      graphql_name 'DependencyFirewallPolicyAttributesType'
      description 'Represents policy fields related to the dependency firewall policy.'

      field :source, Types::SecurityOrchestration::SecurityPolicySourceType,
        null: false,
        description: 'Source of the policy. Its fields depend on the source type.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
