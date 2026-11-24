# frozen_string_literal: true

module Resolvers
  module Security
    class FindingTokenStatusResolver < BaseResolver
      type Types::Vulnerabilities::FindingTokenStatusType, null: true

      alias_method :security_finding, :object

      def resolve
        return unless should_display_finding_token_status?

        BatchLoader::GraphQL.for(security_finding.id).batch do |finding_ids, loader|
          ::Security::FindingTokenStatus
            .with_security_finding_ids(finding_ids)
            .find_each do |token_status|
              loader.call(token_status.security_finding_id, token_status)
            end
        end
      end

      private

      def should_display_finding_token_status?
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
