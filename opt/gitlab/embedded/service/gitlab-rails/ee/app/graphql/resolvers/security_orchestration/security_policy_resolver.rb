# frozen_string_literal: true

module Resolvers
  module SecurityOrchestration
    class SecurityPolicyResolver < BaseResolver
      include ResolvesOrchestrationPolicy
      include ConstructSecurityPolicies

      type Types::SecurityOrchestration::SecurityPolicyType, null: true
      calls_gitaly!

      argument :relationship, ::Types::SecurityOrchestration::SecurityPolicyRelationTypeEnum,
        description: 'Filter policies by the given policy relationship.',
        required: false,
        default_value: :direct

      argument :include_unscoped, GraphQL::Types::Boolean,
        description: 'Filter policies that are scoped to the project.',
        required: false,
        default_value: true

      argument :type, ::Types::SecurityOrchestration::PolicyTypeEnum,
        description: 'Filter policies by type.',
        required: false,
        default_value: nil

      def resolve(**args)
        policies = ::Security::AllPoliciesFinder.new(context[:current_user], object, args).execute
        context[:security_policy_parent] = object
        construct_security_policies(policies)
      end
    end
  end
end
