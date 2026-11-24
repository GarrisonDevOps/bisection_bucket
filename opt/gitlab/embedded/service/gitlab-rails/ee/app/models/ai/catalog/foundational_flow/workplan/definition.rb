# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module Workplan
        module Definition
          module_function

          REFERENCE = 'workplan/v1'
          private_constant :REFERENCE

          # The workplan goal is the full prompt with the work item URL embedded, so
          # resolve the work item from that URL to link the flow session to it.
          NOTEABLE_RESOLVER = ->(project:, goal:) do
            iid = goal.to_s.match(%r{/-/(?:work_items|issues)/(\d+)})&.captures&.first&.to_i
            next unless iid&.positive?

            project.work_items.find_by_iid(iid)
          end
          private_constant :NOTEABLE_RESOLVER

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|Generate Workplan"
              ),
              description: s_(
                "FoundationalFlow|Draft a Why/How/What workplan for a work item and write it to the " \
                  "Workplan widget."
              ),
              avatar: "gitlab-duo-flow.png",
              feature_maturity: "experimental",
              feature_flag: "workplan",
              # Runs server-side so the plan is generated asynchronously without
              # opening Duo Chat. Mirrors the Planner chat agent's GitLab-only tool needs
              # (read/update work items), so no file, git, or command privileges are granted.
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB
              ],
              # The flow reads the repository through GitLab API tools only, so it needs no checkout.
              coding_environment: "none",
              environment: "web",
              triggers: [],
              supported_events: [
                ::Ai::FlowTrigger::EVENT_TYPES[:mention],
                ::Ai::FlowTrigger::EVENT_TYPES[:assign],
                ::Ai::FlowTrigger::EVENT_TYPES[:work_item]
              ],
              supported_resource_types: [::Issue],
              goal_templates: ::Ai::Catalog::GoalTemplates::Workplan,
              noteable_resolver: NOTEABLE_RESOLVER,
              # 1.1.0 ends with a readiness_score write. 1.3.0 also splits the plan into child
              # Tasks with BLOCKED_BY links, which only Software Factory triage uses.
              flow_version_resolver: ->(container:, user:, additional_context:) do
                next [REFERENCE, '1.3.0'] if container && ::Gitlab::Ai::SoftwareFactory.enabled?(container)

                [REFERENCE, '1.1.0']
              end
            }
          end
        end
      end
    end
  end
end
