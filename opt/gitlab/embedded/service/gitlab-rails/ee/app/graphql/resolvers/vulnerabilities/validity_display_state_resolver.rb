# frozen_string_literal: true

module Resolvers
  module Vulnerabilities
    class ValidityDisplayStateResolver < BaseResolver
      include ::Security::ResolvesValidityDisplayState

      type Types::Vulnerabilities::ValidityDisplayStateEnum, null: true

      alias_method :vulnerability, :object

      def resolve
        return unless should_display?

        finding = vulnerability.finding
        resolve_validity_display_state(finding, id_attribute: :vulnerability_occurrence_id) do |finding_ids|
          ::Vulnerabilities::FindingTokenStatus.with_vulnerability_occurrence_ids(finding_ids)
        end
      end

      private

      def should_display?
        return false unless vulnerability.report_type == 'secret_detection'
        return false unless vulnerability.finding
        return false unless project.licensed_feature_available?(:secret_detection_validity_checks)

        project.security_setting&.validity_checks_enabled
      end

      def project
        vulnerability.project
      end
    end
  end
end
