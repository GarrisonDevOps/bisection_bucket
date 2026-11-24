# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class EnablementCheckService
      # Each field is computed on first read, so a GraphQL query only pays for
      # the fields it selects. `checks` in particular runs the Duo entitlement
      # lookup, which clients that only read `enabled` never ask for.
      class Result
        include Gitlab::Utils::StrongMemoize

        def initialize(project:, current_user:)
          @project = project
          @current_user = current_user
        end

        def enabled
          Ai::DuoWorkflow.duo_agent_platform_available_for_project?(project)
        end
        strong_memoize_attr :enabled

        def create_duo_workflow_for_ci_allowed
          Ability.allowed?(current_user, :create_duo_workflow_for_ci, project)
        end
        strong_memoize_attr :create_duo_workflow_for_ci_allowed

        def checks
          [
            {
              name: :feature_flag,
              value: true,
              message: _("duo_workflow feature flag must be enabled.")
            },
            {
              name: :duo_features_enabled,
              value: project.duo_features_enabled,
              message: _("Project must have GitLab Duo features enabled.")
            }, {
              name: :developer_access,
              value: Ability.allowed?(current_user, :duo_workflow, project),
              message: _("User must have permission to use Duo Workflows in the project.")
            }, {
              name: :identity_verification,
              value: !current_user&.dap_identity_verification_required?(project),
              message: _("User must verify their identity before using GitLab Duo Agent Platform.")
            }, {
              name: :feature_available,
              value: ::Gitlab::Llm::StageCheck.available?(project,
                :duo_workflow) && current_user&.allowed_to_use?(:duo_agent_platform),
              message: _("duo_workflow licensed feature must be available for the project and experimental " \
                "features must be enabled.")
            }
          ]
        end
        strong_memoize_attr :checks

        def remote_flows_enabled
          project.duo_remote_flows_enabled
        end

        def foundational_flows_enabled
          project.duo_foundational_flows_enabled
        end

        def enabled_foundational_flows
          project.enabled_foundational_flow_references
        end
        strong_memoize_attr :enabled_foundational_flows

        private

        attr_reader :project, :current_user
      end

      def initialize(project:, current_user:)
        @project = project
        @current_user = current_user
      end

      def execute
        return unless Ability.allowed?(@current_user, :read_project, @project)

        Result.new(project: @project, current_user: @current_user)
      end
    end
  end
end
