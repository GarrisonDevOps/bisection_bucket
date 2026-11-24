# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module RecommendReviewers
        module Definition
          module_function

          REFERENCE = 'recommend_reviewers/v1'
          private_constant :REFERENCE

          TRIGGER_FILTER = {
            'rules' => [
              { 'field' => 'action', 'operator' => 'in', 'value' => ['created'] }
            ]
          }.freeze
          private_constant :TRIGGER_FILTER

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|Recommend Reviewers"
              ),
              description: s_(
                "FoundationalFlow|Recommend reviewers for merge requests based on availability, " \
                  "workload, and timezone."
              ),
              feature_maturity: "beta",
              coding_environment: "none",
              ai_feature: "recommend_reviewers_assign",
              avatar: "gitlab-duo-flow.png",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB
              ],
              triggers: [
                ::Ai::FlowTrigger::EVENT_TYPES[:merge_request]
              ],
              precondition: TRIGGER_FILTER,
              default_trigger_filter: {
                'merge_request' => TRIGGER_FILTER
              },
              # The agent session system notes already link the session, so the
              # progress note only adds noise.
              suppress_progress_note: true,
              flow_version: '^3.0.0',
              supported_resource_types: [::MergeRequest],
              additional_context_resolver: Context
            }
          end
        end
      end
    end
  end
end
