# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class Confirm < BaseMutation
      graphql_name 'VulnerabilityConfirm'

      authorize :confirm_vulnerability

      authorize_granular_token permissions: :confirm_vulnerability,
        boundary_argument: :id, boundary: :project,
        boundary_type: :project

      def self.state_transition_name_past_tense
        "confirmed"
      end

      def self.authorization_scopes
        [:api, :ai_workflows]
      end

      prepend Mutations::VulnerabilityStateTransitions

      private

      def transition_vulnerability(vulnerability, comment)
        ::Vulnerabilities::ConfirmService.new(current_user, vulnerability, comment).execute
      end
    end
  end
end
