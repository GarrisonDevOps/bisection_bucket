# frozen_string_literal: true

module Resolvers
  module SecurityOrchestration
    # rubocop:disable Graphql/ResolverType -- type is defined and resolve method is inherited from the parent class
    class ApprovalPolicyResolver < ScanResultPolicyResolver
      type Types::SecurityOrchestration::ApprovalPolicyType, null: true
    end
    # rubocop:enable Graphql/ResolverType
  end
end
