# frozen_string_literal: true

module Resolvers
  module SecurityOrchestration
    class PolicyViolationsResolver < BaseResolver
      include Gitlab::Graphql::Authorize::AuthorizeResource

      type ::Types::SecurityOrchestration::PolicyViolationDetailsType, null: true

      authorizes_object!
      authorize :read_security_resource

      description 'Approval policy violations detected for the merge request.'

      def resolve(**_args)
        ::Security::ScanResultPolicies::PolicyViolationDetails.new(object)
      end
    end
  end
end
