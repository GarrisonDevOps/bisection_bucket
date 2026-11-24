# frozen_string_literal: true

module Types
  module SecurityOrchestration
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled in the resolver
    # this represents a hash, from the orchestration policy configuration
    # the authorization happens for that configuration
    class ScanExecutionPolicyAttributesType < BaseObject
      graphql_name 'ScanExecutionPolicyAttributesType'
      description 'Represents policy fields related to the scan execution policy.'

      field :deprecated_properties, [::GraphQL::Types::String], null: true,
        description: 'All deprecated properties in the policy.',
        experiment: { milestone: '17.3' }
      field :source, Types::SecurityOrchestration::SecurityPolicySourceType,
        null: false,
        description: 'Source of the policy. Its fields depend on the source type.'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
