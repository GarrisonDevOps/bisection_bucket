# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class Resolve < BaseMutation
      graphql_name 'VulnerabilityResolve'

      authorize :resolve_vulnerability

      authorize_granular_token permissions: :resolve_vulnerability,
        boundary_argument: :id, boundary: :project,
        boundary_type: :project

      def self.state_transition_name_past_tense
        "resolved"
      end

      prepend Mutations::VulnerabilityStateTransitions

      private

      def transition_vulnerability(vulnerability, comment)
        ::Vulnerabilities::ResolveService.new(current_user, vulnerability, comment).execute
      end
    end
  end
end
