# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module AdditionalContext
      # Builds agent_platform_standard_context (schema: json_schemas/agent_platform/agent_platform_standard_context).
      module StandardContextBuilder
        def self.build(project:, current_user:, service_account:, source_branch:, session_url:, ref:)
          primary_branch =
            if source_branch && project.repository.branch_exists?(source_branch)
              source_branch
            else
              project.default_branch_or_main
            end

          {
            "workload_branch" => ref,
            "primary_branch" => primary_branch,
            "session_owner_id" => current_user.id.to_s,
            "session_owner_username" => current_user.username,
            "service_account_name" => service_account.username,
            "session_url" => session_url
          }
        end
      end
    end
  end
end
