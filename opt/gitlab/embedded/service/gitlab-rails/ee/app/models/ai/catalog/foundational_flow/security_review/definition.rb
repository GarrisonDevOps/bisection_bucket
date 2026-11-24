# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module SecurityReview
        module Definition
          module_function

          REFERENCE = 'security_review/v1'

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              flow_version: '^2.0.0',
              display_name: s_(
                "FoundationalFlow|Security Review"
              ),
              description: s_(
                "FoundationalFlow|Review merge request code changes for business logic security vulnerabilities."
              ),
              avatar: "security-flow.png",
              feature_maturity: "beta",
              ai_feature: "security_review",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB
              ],
              environment: "web",
              ultimate_only: true,
              # Security Review owns its own discussion threads (it replies to and
              # resolves them in its validate_and_publish step), so it skips the
              # generic mention progress note.
              suppress_mention_progress_note: true,
              # A security assessment must never be readable beyond the project
              # members, so on a non-private project the mention-triggered reply
              # is posted as an internal note. Private projects keep the threaded
              # reply (https://gitlab.com/gitlab-org/gitlab/-/work_items/606308).
              force_internal_mention_replies: true,
              triggers: [
                ::Ai::FlowTrigger::EVENT_TYPES[:assign_reviewer],
                ::Ai::FlowTrigger::EVENT_TYPES[:mention]
              ],
              goal_templates: ::Ai::Catalog::GoalTemplates::SecurityReview
            }
          end
        end
      end
    end
  end
end
