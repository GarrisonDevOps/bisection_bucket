# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module SkillguardScan
        module Definition
          module_function

          REFERENCE = 'skillguard_scan/v1'

          SCANNER_EXTERNAL_ID = 'skillguard'

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|SkillGuard Security Scan"
              ),
              description: s_(
                "FoundationalFlow|Analyze AI agent skill files for security risks using " \
                  "deterministic static analysis and LLM-powered audit."
              ),
              avatar: "security-flow.png",
              feature_maturity: "experimental",
              feature_flag: "skillguard_scan_flow",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS
              ],
              environment: "ambient",
              triggers: [::Ai::FlowTrigger::EVENT_TYPES[:pipeline_hooks]],
              supported_events: [::Ai::FlowTrigger::EVENT_TYPES[:pipeline_hooks]],
              # pipeline_hooks fires on every status transition, so scope to success
              # or one pipeline starts a scan on running and again on completion.
              default_trigger_filter: {
                'pipeline_hooks' => {
                  'match' => 'all',
                  'rules' => [
                    { 'field' => 'object_attributes.status', 'operator' => 'eq', 'value' => 'success' }
                  ]
                }
              },
              # Only scan the default branch; merge request and feature-branch pipelines are skipped.
              precondition: {
                'match' => 'all',
                'rules' => [
                  { 'field' => 'object_attributes.default_branch', 'operator' => 'eq', 'value' => true }
                ]
              },
              # Triggered runs need an attached SkillGuard scan profile.
              run_eligibility_resolver: RunEligibility,
              ultimate_only: true,
              report_artifacts: { sast: ['gl-sast-report.json'] }
            }
          end
        end
      end
    end
  end
end
