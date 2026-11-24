# frozen_string_literal: true

module Types
  module SecurityOrchestration
    # rubocop: disable Graphql/AuthorizeTypes -- Authorization handled in the resolver
    # this represents a hash, from the orchestration policy configuration
    # the authorization happens for that configuration
    class ApprovalPolicyType < ScanResultPolicyType
      graphql_name 'ApprovalPolicy'
      description 'Represents the approval policy'
    end
    # rubocop: enable Graphql/AuthorizeTypes
  end
end
