# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module Developer
        module Definition
          module_function

          REFERENCE = 'developer/v1'
          private_constant :REFERENCE

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|Developer"
              ),
              description: s_(
                "FoundationalFlow|Turn feedback into actionable merge requests or issues."
              ),
              feature_maturity: "ga",
              avatar: "gitlab-duo-flow.png",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT
              ],
              required_agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS
              ],
              environment: "web",
              triggers: [
                ::Ai::FlowTrigger::EVENT_TYPES[:assign],
                ::Ai::FlowTrigger::EVENT_TYPES[:mention]
              ],
              goal_templates: ::Ai::Catalog::GoalTemplates::Developer,
              accepts_trigger_goal: true,
              schedulable: true,
              flow_version: '^3.0.0',
              # 4.0.0 rests after each turn instead of ending, so the session can be
              # continued.
              flow_version_resolver: ->(container:, user:, additional_context:) do
                next unless ::Feature.enabled?(:duo_developer_continuable_sessions, user) ||
                  ::Feature.enabled?(:duo_developer_continuable_sessions, container&.root_ancestor)

                [REFERENCE, '^4.0.0']
              end,
              ai_feature: "duo_developer"
            }
          end
        end
      end
    end
  end
end
