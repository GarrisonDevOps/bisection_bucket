# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class RevertToDetected < BaseMutation
      graphql_name 'VulnerabilityRevertToDetected'

      authorize :revert_vulnerability

      authorize_granular_token permissions: :revert_vulnerability,
        boundary_argument: :id, boundary: :project,
        boundary_type: :project

      def self.authorization_scopes
        [:api, :ai_workflows]
      end

      def self.state_transition_name_past_tense
        "reverted to detected"
      end

      prepend Mutations::VulnerabilityStateTransitions

      private

      def transition_vulnerability(vulnerability, comment)
        ::Vulnerabilities::RevertToDetectedService.new(current_user, vulnerability, comment).execute
      end
    end
  end
end
