# frozen_string_literal: true

module Ai
  module DuoWorkflows
    module DeclaredPrivileges
      PRIVILEGES = ::Ai::DuoWorkflows::Workflow::AgentPrivileges

      # The Duo Workflow Service treats each read-write privilege as a superset of its read-only form.
      READ_ONLY_FORMS = {
        PRIVILEGES::READ_WRITE_GITLAB => PRIVILEGES::READ_ONLY_GITLAB,
        PRIVILEGES::READ_WRITE_FILES => PRIVILEGES::READ_ONLY_FILES
      }.freeze

      # The Duo Workflow Service enables MCP tools whatever is granted,
      # so capping this privilege would only break their pre-approval.
      UNCAPPED = [PRIVILEGES::RUN_MCP_TOOLS].freeze

      def self.apply!(params, definition)
        declared = definition.agent_privileges
        local = ::Ai::ToolRules::GovernanceSurface::LOCAL_ENVIRONMENTS.include?(params[:environment].to_s)
        requested = params.fetch(:agent_privileges) { local ? PRIVILEGES::DEFAULT_PRIVILEGES : declared }
        granted = limit(requested, definition)
        pre_approved = params.fetch(:pre_approved_agent_privileges) do
          # Local sessions ask the user before acting, so keep the column default.
          next definition.pre_approved_agent_privileges unless local

          ::Ai::DuoWorkflows::Workflow.column_defaults['pre_approved_agent_privileges']
        end

        params[:agent_privileges] = granted
        params[:pre_approved_agent_privileges] = with_read_only_forms(pre_approved) & granted
      end

      def self.limit(privileges, definition)
        declared = definition.agent_privileges
        (privileges & with_read_only_forms(declared)) | (with_read_only_forms(privileges) & declared) |
          (privileges & UNCAPPED)
      end

      def self.foundational_flow(workflow_definition)
        # rubocop:disable Gitlab/Ai/AvoidFoundationalFlowStringLookup -- the reference comes from the request
        ::Ai::Catalog::FoundationalFlow[workflow_definition]
        # rubocop:enable Gitlab/Ai/AvoidFoundationalFlowStringLookup
      end

      def self.with_read_only_forms(privileges)
        privileges | READ_ONLY_FORMS.values_at(*privileges).compact
      end
    end
  end
end
