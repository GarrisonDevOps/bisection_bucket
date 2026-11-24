# frozen_string_literal: true

module Resolvers
  module SecurityOrchestration
    class ScanResultPolicyResolver < BaseResolver
      include ResolvesOrchestrationPolicy
      include ConstructApprovalPolicies

      type Types::SecurityOrchestration::ScanResultPolicyType, null: true

      argument :relationship, ::Types::SecurityOrchestration::SecurityPolicyRelationTypeEnum,
        description: 'Filter policies by the given policy relationship. Default is DIRECT.',
        required: false,
        default_value: :direct

      argument :include_unscoped, GraphQL::Types::Boolean,
        description: 'Filter policies that are scoped to the project.',
        required: false,
        default_value: true

      argument :deduplicate_policies, GraphQL::Types::Boolean,
        description: 'Remove duplicate policies when the same policy is applied via multiple routes.',
        required: false,
        default_value: false

      def resolve(**args)
        policies = ::Security::ScanResultPoliciesFinder.new(context[:current_user], object,
          args.merge(include_invalid: true)).execute
        construct_scan_result_policies(policies)
      end
    end
  end
end
