# frozen_string_literal: true

module EE
  module Projects
    module LookAheadPreloads
      extend ActiveSupport::Concern
      extend ::Gitlab::Utils::Override

      private

      override :preloads
      def preloads
        super.merge(
          has_jira_vulnerability_issue_creation_enabled: [:jira_imports, :jira_integration],
          vulnerability_statistic: [:vulnerability_statistic],
          merge_requests_disable_committers_approval: [{ group: :group_merge_request_approval_setting }],
          ai_xray_reports: [:xray_reports],
          analyzer_statuses: [:analyzer_statuses],
          container_scanning_for_registry_enabled: [:security_setting]
        )
      end
    end
  end
end
