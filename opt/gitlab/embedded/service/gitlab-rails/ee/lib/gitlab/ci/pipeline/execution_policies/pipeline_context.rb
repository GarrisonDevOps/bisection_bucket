# frozen_string_literal: true

# This class encapsulates functionality related to Scan and Pipeline Execution Policies.
module Gitlab
  module Ci
    module Pipeline
      module ExecutionPolicies
        class PipelineContext
          include ::Gitlab::Utils::StrongMemoize

          attr_reader :trigger

          # rubocop:disable Metrics/ParameterLists -- Explicit parameters needed to replace command object delegation
          def initialize(
            project:, source: nil, current_user: nil, ref: nil, sha_context: nil,
            variables_attributes: nil, scan_execution_policy_context_block: nil,
            pipeline_execution_policy_context_block: nil, chat_data: nil,
            merge_request: nil, schedule: nil, bridge: nil, trigger: nil)
            # rubocop:enable Metrics/ParameterLists
            @project = project
            @source = source
            @current_user = current_user
            @ref = ref
            @sha_context = sha_context
            @variables_attributes = variables_attributes
            @scan_execution_policy_context_block = scan_execution_policy_context_block
            @pipeline_execution_policy_context_block = pipeline_execution_policy_context_block
            @chat_data = chat_data
            @merge_request = merge_request
            @schedule = schedule
            @bridge = bridge
            @trigger = trigger
          end

          def pipeline_execution_context
            args = {
              context: self,
              project: project,
              source: source,
              current_user: current_user,
              ref: ref,
              sha_context: sha_context,
              variables_attributes: variables_attributes,
              chat_data: chat_data,
              merge_request: merge_request,
              schedule: schedule,
              trigger: trigger,
              is_parent_pipeline_policy: parent_pipeline_policy?
            }

            args = pipeline_execution_policy_context_block.call(args) if pipeline_execution_policy_context_block

            ::Gitlab::Ci::Pipeline::PipelineExecutionPolicies::PipelineContext.new(**args)
          end
          strong_memoize_attr :pipeline_execution_context

          def scan_execution_context(ref)
            strong_memoize_with(:scan_execution_context, ref) do
              args = { project: project, ref: ref, current_user: current_user, source: source }
              args = scan_execution_policy_context_block.call(args) if scan_execution_policy_context_block

              ::Gitlab::Ci::Pipeline::ScanExecutionPolicies::PipelineContext.new(**args)
            end
          end

          def skip_ci_allowed?(ref:)
            pipeline_execution_context.skip_ci_allowed? && scan_execution_context(ref).skip_ci_allowed?
          end

          def no_pipeline_allowed?(ref:)
            pipeline_execution_context.no_pipeline_allowed? && scan_execution_context(ref).no_pipeline_allowed?
          end

          def job_options(ref:, job_name:)
            pipeline_execution_context.job_options || scan_execution_context(ref).job_options(job_name)
          end

          private

          attr_reader :project, :source, :current_user, :ref, :sha_context, :variables_attributes,
            :scan_execution_policy_context_block, :pipeline_execution_policy_context_block,
            :chat_data, :merge_request, :schedule, :bridge

          def parent_pipeline_policy?
            return false unless source&.to_sym == :parent_pipeline

            parent_execution_policy_pipeline? || parent_scheduled_execution_policy_pipeline?
          end

          def parent_execution_policy_pipeline?
            bridge&.source&.to_sym == :pipeline_execution_policy
          end

          def parent_scheduled_execution_policy_pipeline?
            bridge&.source&.to_sym == :pipeline_execution_policy_schedule
          end
        end
      end
    end
  end
end
