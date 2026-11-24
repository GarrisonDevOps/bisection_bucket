# frozen_string_literal: true

module EE
  module API
    module Helpers
      module MergeRequestsHelpers
        extend ActiveSupport::Concern
        include McpHelpers

        prepended do
          params :ee_approval_params do
            optional :approval_password,
              type: String,
              desc: "Current user's password, needed if [user re-authentication to approve]" \
                "(https://docs.gitlab.com/user/project/merge_requests/approvals/settings/" \
                "#require-user-re-authentication-to-approve) is enabled in the project settings. " \
                "Always fails if the group or GitLab Self-Managed instance is configured to force " \
                "SAML authentication.",
              documentation: { example: 'secret' }
          end
        end

        # Filters out files that are excluded from Duo AI context based on project settings
        # Only applies filtering when the request is from MCP
        #
        # @param diffs [Array] Array of diff objects
        # @param project [Project] The project to check exclusion settings for
        # @return [Array] Array of diffs with excluded files removed (if MCP request), or original diffs
        def filter_diffs_for_mcp(diffs, project)
          return diffs unless mcp_request?
          return diffs unless project

          file_paths = diffs.filter_map { |diff| diff.new_path || diff.old_path }.uniq
          return diffs if file_paths.empty?

          result = ::Ai::FileExclusionService.new(project).execute(file_paths)
          return diffs unless result.success?

          excluded_paths = result.payload.filter_map { |f| f[:path] if f[:excluded] }.to_set

          diffs.reject { |diff| excluded_paths.include?(diff.new_path) || excluded_paths.include?(diff.old_path) }
        end
      end
    end
  end
end
