# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module RiskClassification
        module Definition
          module_function

          REFERENCE = 'risk_classification/v1'
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
                "FoundationalFlow|Risk Assessment"
              ),
              description: s_(
                "FoundationalFlow|Assess the risk of a merge request so review effort can be " \
                  "routed to the changes that warrant it."
              ),
              avatar: "gitlab-duo-flow.png",
              feature_maturity: "experimental",
              ai_feature: "risk_classification",
              environment: "web",
              ultimate_only: true,
              feature_flag: "duo_mr_risk_classification",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB
              ],
              suppress_agent_session_note: true,
              suppress_progress_note: true,
              supported_resource_types: [::MergeRequest],
              triggers: [
                ::Ai::FlowTrigger::EVENT_TYPES[:merge_request]
              ],
              precondition: TRIGGER_FILTER,
              default_trigger_filter: {
                'merge_request' => TRIGGER_FILTER
              },
              additional_context_resolver: Context,
              # 2.0.0 reads files through the API only, so it can later run without a checkout.
              flow_version_resolver: ->(container:, user:, additional_context:) do
                [REFERENCE, '^2.0.0'] if ::Feature.enabled?(:duo_mr_risk_classification_no_checkout, container)
              end,
              on_session_created: ->(resource:) do
                assessment = ::MergeRequests::RiskAssessment.ensure_for!(resource)
                # Locked so an ending session's hook cannot fail the row between this read and the enqueue.
                assessment.with_lock { assessment.enqueue }
              end,
              on_session_finished: OnSessionEnded,
              on_session_failed: OnSessionEnded,
              on_session_stopped: OnSessionEnded
            }
          end
        end
      end
    end
  end
end
