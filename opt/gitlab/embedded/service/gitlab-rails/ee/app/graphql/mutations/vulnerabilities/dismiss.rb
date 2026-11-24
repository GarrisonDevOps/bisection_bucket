# frozen_string_literal: true

module Mutations
  module Vulnerabilities
    class Dismiss < BaseMutation
      graphql_name 'VulnerabilityDismiss'

      authorize :dismiss_vulnerability

      authorize_granular_token permissions: :dismiss_vulnerability,
        boundary_argument: :id, boundary: :project,
        boundary_type: :project

      def self.state_transition_name_past_tense
        "dismissed"
      end

      def self.authorization_scopes
        [:api, :ai_workflows]
      end

      prepend Mutations::VulnerabilityStateTransitions

      argument :dismissal_reason,
        Types::Vulnerabilities::DismissalReasonEnum,
        required: false,
        description: 'Reason why vulnerability should be dismissed.'

      def resolve(id:, comment: nil, dismissal_reason: nil)
        vulnerability = authorized_find!(id: id)
        result = transition_vulnerability(vulnerability, comment, dismissal_reason)

        {
          vulnerability: result,
          errors: result.errors.full_messages || []
        }
      end

      private

      def transition_vulnerability(vulnerability, comment, dismissal_reason)
        ::Vulnerabilities::DismissService.new(current_user, vulnerability, comment, dismissal_reason).execute
      end
    end
  end
end
