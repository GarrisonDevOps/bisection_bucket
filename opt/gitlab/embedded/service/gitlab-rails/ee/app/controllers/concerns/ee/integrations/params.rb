# frozen_string_literal: true

module EE
  module Integrations
    module Params
      extend ::Gitlab::Utils::Override

      ALLOWED_PARAMS_EE = [
        :artifact_registry_project_id,
        :artifact_registry_location,
        :artifact_registry_repositories,
        :issues_enabled,
        :multiproject_enabled,
        :pass_unstable,
        :project_keys,
        :repository_url,
        :static_context,
        :vulnerabilities_enabled,
        :vulnerabilities_issuetype,
        :customize_jira_issue_enabled,
        :workload_identity_federation_project_id,
        :workload_identity_federation_project_number,
        :workload_identity_pool_id,
        :workload_identity_pool_project_number,
        :workload_identity_pool_provider_id,
        :jira_check_enabled,
        :jira_exists_check_enabled,
        :jira_assignee_check_enabled,
        :jira_status_check_enabled,
        :jira_allowed_statuses_as_string
      ].freeze

      override :integration_params
      def integration_params
        return_value = super
        parse_jira_project_keys(return_value)

        return_value
      end

      override :allowed_integration_params
      def allowed_integration_params
        super + ALLOWED_PARAMS_EE
      end

      def parse_jira_project_keys(return_value)
        return unless return_value.dig(:integration, :project_keys)

        return_value[:integration][:project_keys] = return_value[:integration][:project_keys].split(',')
      end
    end
  end
end
