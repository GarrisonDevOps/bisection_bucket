# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module ReadinessScore
        module Definition
          module_function

          # Goal is the work item URL; resolve it to link the flow session to the work item.
          NOTEABLE_RESOLVER = ->(project:, goal:) do
            iid = goal.to_s.match(%r{/-/(?:work_items|issues)/(\d+)})&.captures&.first&.to_i
            next unless iid&.positive?

            project.work_items.find_by_iid(iid)
          end
          private_constant :NOTEABLE_RESOLVER

          def configuration
            {
              foundational_flow_reference: "readiness_score/v1",
              display_name: s_(
                "FoundationalFlow|Readiness Score"
              ),
              description: s_(
                "FoundationalFlow|Score readiness of a work item for handoff based on its specification and plan."
              ),
              avatar: "gitlab-duo-flow.png",
              feature_maturity: "experimental",
              feature_flag: "workplan",
              # Server-side flow: reads the work item and writes the score back
              # via the work item update mutation. No file, git, or command access.
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB
              ],
              # The flow reads the work item through GitLab API tools only, so it needs no checkout.
              coding_environment: "none",
              environment: "web",
              triggers: [],
              supported_events: [],
              goal_templates: ::Ai::Catalog::GoalTemplates::ReadinessScore,
              noteable_resolver: NOTEABLE_RESOLVER
            }
          end
        end
      end
    end
  end
end
