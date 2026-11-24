# frozen_string_literal: true

module Ai
  module Catalog
    class FoundationalFlow
      module FixPipeline
        module Definition
          module_function

          REFERENCE = 'fix_pipeline/v1'
          private_constant :REFERENCE

          # The fix_pipeline flow sets the goal to the failed pipeline's URL. Both the
          # noteable and source-pipeline resolvers start from that pipeline, so the
          # lookup lives in one place: the noteable resolver derives its merge request,
          # the source-pipeline resolver returns the pipeline itself.
          RESOLVER = ->(project:, goal:) do
            pipeline_id = goal.to_s.match(%r{/-/pipelines/(\d+)})&.captures&.first&.to_i
            next unless pipeline_id&.positive?

            Ci::Pipeline.for_project(project).find_by_id(pipeline_id)
          end
          private_constant :RESOLVER

          def configuration
            {
              foundational_flow_reference: REFERENCE,
              display_name: s_(
                "FoundationalFlow|Fix CI/CD Pipeline"
              ),
              description: s_(
                "FoundationalFlow|Diagnose and fix issues in your GitLab CI/CD pipeline."
              ),
              feature_maturity: "ga",
              avatar: "fix-pipeline-flow.png",
              agent_privileges: [
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_FILES,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_ONLY_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::READ_WRITE_GITLAB,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::RUN_COMMANDS,
                ::Ai::DuoWorkflows::Workflow::AgentPrivileges::USE_GIT
              ],
              environment: "web",
              flow_version: '1.0.4',
              triggers: [],
              supported_events: [::Ai::FlowTrigger::EVENT_TYPES[:pipeline_hooks]],
              precondition: {
                'match' => 'all',
                'rules' => [
                  { 'field' => 'object_attributes.status', 'operator' => 'eq', 'value' => 'failed' }
                ]
              },
              noteable_resolver: ->(project:, goal:) do
                pipeline = RESOLVER.call(project: project, goal: goal)

                pipeline&.all_merge_requests_by_recency&.opened&.first
              end,
              source_pipeline_resolver: RESOLVER,
              reuse_open_merge_request: true,
              flow_version_resolver: ->(container:, user:, additional_context:) do
                if ::Feature.enabled?(:fix_pipeline_experimental, container) ||
                    ::Feature.enabled?(:fix_pipeline_experimental, container.root_ancestor)
                  ['fix_pipeline/experimental', ::Ai::Catalog::FoundationalFlow::DEFAULT_FLOW_VERSION]
                end
              end
            }
          end
        end
      end
    end
  end
end
