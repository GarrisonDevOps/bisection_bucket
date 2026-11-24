# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module ResolveDependencyBump
        module Definition
          module_function

          REFERENCE = 'resolve_dependency_bump/experimental'
          private_constant :REFERENCE

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|Resolve Dependency Bump Breaking Changes"
              ),
              description: s_(
                "FoundationalFlow|Analyze and fix breaking changes caused by dependency bumps."
              ),
              feature_maturity: "beta",
              ai_feature: "resolve_dependency_bump",
              avatar: "security-flow.png",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT
              ],
              environment: "ambient",
              triggers: [
                ::Ai::FlowTrigger::EVENT_TYPES[:mention]
              ],
              goal_templates: ::Ai::Catalog::GoalTemplates::ResolveDependencyBump,
              ultimate_only: true
            }
          end
        end
      end
    end
  end
end
