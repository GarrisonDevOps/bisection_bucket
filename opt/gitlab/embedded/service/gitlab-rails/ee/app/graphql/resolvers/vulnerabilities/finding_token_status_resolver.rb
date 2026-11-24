# frozen_string_literal: true

module Resolvers
  module Vulnerabilities
    class FindingTokenStatusResolver < BaseResolver
      type Types::Vulnerabilities::FindingTokenStatusType, null: true

      alias_method :vulnerability, :object

      def resolve
        return unless should_display_finding_token_status?

        return unless vulnerability.finding

        BatchLoader::GraphQL.for(vulnerability.finding.id).batch do |finding_ids, loader|
          ::Vulnerabilities::FindingTokenStatus
            .with_vulnerability_occurrence_ids(finding_ids)
            .find_each do |token_status|
              loader.call(token_status.vulnerability_occurrence_id, token_status)
            end
        end
      end

      private

      def should_display_finding_token_status?
        return false unless vulnerability.report_type == 'secret_detection'
        return false unless project.licensed_feature_available?(:secret_detection_validity_checks)

        project.security_setting&.validity_checks_enabled
      end

      def project
        vulnerability.project
      end
    end
  end
end
