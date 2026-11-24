# frozen_string_literal: true

module Resolvers
  module Security
    class ValidityDisplayStateResolver < BaseResolver
      include ::Security::ResolvesValidityDisplayState

      type Types::Vulnerabilities::ValidityDisplayStateEnum, null: true

      alias_method :security_finding, :object

      def resolve
        return unless should_display?

        resolve_validity_display_state(security_finding, id_attribute: :security_finding_id) do |finding_ids|
          ::Security::FindingTokenStatus.with_security_finding_ids(finding_ids)
        end
      end

      private

      def should_display?
        return false unless security_finding
        return false unless security_finding.report_type == 'secret_detection'
        return false unless project.licensed_feature_available?(:secret_detection_validity_checks)
        return false unless project.security_setting&.validity_checks_enabled
        return false unless Ability.allowed?(current_user, :read_vulnerability, project)

        true
      end

      def project
        security_finding.project
      end
    end
  end
end
