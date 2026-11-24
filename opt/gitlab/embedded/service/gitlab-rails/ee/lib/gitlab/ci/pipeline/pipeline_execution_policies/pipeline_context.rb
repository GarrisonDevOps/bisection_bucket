# frozen_string_literal: true

# This class encapsulates functionality related to Pipeline Execution Policies and is used during pipeline creation.
module Gitlab
  module Ci
    module Pipeline
      module PipelineExecutionPolicies
        OverrideStagesConflictError = Class.new(StandardError)
        PolicyPipelineCreationResult = Struct.new(:response, :job_name_mappings, :job_count, keyword_init: true)

        class PipelineContext
          include ::Gitlab::Utils::StrongMemoize
          include ::Gitlab::Loggable

          HISTOGRAMS = {
            single_pipeline: :gitlab_security_policies_pipeline_execution_policy_dry_run_pipeline,
            all_pipelines: :gitlab_security_policies_pipeline_execution_policy_build_policy_pipelines
          }.freeze

          COMPILE_COST_LOG_DURATION_THRESHOLD_SECONDS = 5
          COMPILE_COST_LOG_JOBS_THRESHOLD = 1_000

          APPLY_ON_EMPTY_PIPELINE_ALWAYS = 'always'
          APPLY_ON_EMPTY_PIPELINE_IF_NO_CONFIG = 'if_no_config'
          APPLY_ON_EMPTY_PIPELINE_NEVER = 'never'

          attr_reader :policy_pipelines, :override_policy_stages, :injected_policy_stages

          # rubocop:disable Metrics/ParameterLists -- Explicit parameters needed to replace command object delegation
          def initialize(
            context:, project:, source:, current_user:, ref:, sha_context:,
            variables_attributes:, chat_data:, merge_request:, schedule:, trigger:, is_parent_pipeline_policy:,
            current_policy: nil)
            # rubocop:enable Metrics/ParameterLists
            @context = context
            @project = project
            @source = source&.to_sym
            @current_user = current_user
            @ref = ref
            @sha_context = sha_context
            @variables_attributes = variables_attributes
            @chat_data = chat_data
            @merge_request = merge_request
            @schedule = schedule
            @trigger = trigger
            @is_parent_pipeline_policy = is_parent_pipeline_policy
            @current_policy = current_policy
            @policy_pipelines = []
            @override_policy_stages = []
            @injected_policy_stages = []
          end

          def build_policy_pipelines!(partition_id)
            return if creating_policy_pipeline?
            return if policies.empty?

            measure(HISTOGRAMS.fetch(:all_pipelines), labels: { policy_count: policies.size }) do
              policies.each do |policy|
                result = create_pipeline(policy, partition_id)
                response = result.response
                pipeline = response.payload

                if response.success?
                  @policy_pipelines << ::Security::PipelineExecutionPolicy::Pipeline.new(
                    pipeline: pipeline, policy_config: policy,
                    job_name_mappings: result.job_name_mappings
                  )
                elsif pipeline.filtered_as_empty?
                # no-op: we ignore empty pipelines
                elsif block_given?
                  yield response.message
                end
              end
            end
          end

          def policy_management_project_access_allowed?
            creating_policy_pipeline? || scheduled_execution_policy_pipeline? || is_parent_pipeline_policy
          end

          def ci_config_access_allowed?(config_project:, file_path:)
            return false unless policy_management_project_access_allowed?
            return false unless target_project

            ::Gitlab::SafeRequestStore.fetch(
              [self.class.name, 'ci_config_access_allowed', config_project.id, target_project.id, file_path.to_s]
            ) do
              config_project.project_setting.allows_pipeline_execution_policy_ci_config_access?(
                file_path: file_path,
                requesting_project: target_project
              )
            end
          end

          def creating_policy_pipeline?
            return false if scheduled_execution_policy_pipeline?

            current_policy.present?
          end

          def creating_project_pipeline?
            !creating_policy_pipeline?
          end

          def has_execution_policy_pipelines?
            policy_pipelines.present?
          end

          def policy_pipelines_included_components
            policy_pipelines.flat_map do |policy_pipeline|
              policy_pipeline.pipeline.config_metadata.to_h.fetch(:includes, [])
                .filter_map { |include| include[:component] if include[:type] == :component }
            end.uniq
          end

          def scheduled_execution_policy_pipeline?
            source == ::Security::PipelineExecutionPolicies::CreateScheduledPipelineService::PIPELINE_SOURCE
          end

          def creating_any_policy_pipeline?
            creating_policy_pipeline? || scheduled_execution_policy_pipeline?
          end

          def force_pipeline_creation_on_empty_pipeline?(pipeline)
            return false unless has_execution_policy_pipelines?

            strong_memoize_with(:force_pipeline_creation_on_empty_pipeline, pipeline) do
              !empty_pipeline_applicable_policy_pipelines(pipeline).empty?
            end
          end

          # Returns the policy pipelines that should apply based on their apply_on_empty_pipeline setting.
          # This method assumes the pipeline is already determined to be "empty" (no jobs from project CI).
          def empty_pipeline_applicable_policy_pipelines(pipeline)
            strong_memoize_with(:empty_pipeline_applicable_policy_pipelines, pipeline) do
              policy_pipelines.select do |policy_pipeline|
                should_apply_to_empty_pipeline?(policy_pipeline, pipeline)
              end
            end
          end

          def skip_ci_allowed?
            return true unless has_execution_policy_pipelines?

            policy_pipelines.all? { |policy_pipeline| policy_pipeline.skip_ci_allowed?(current_user&.id) }
          end

          def no_pipeline_allowed?
            return true unless has_execution_policy_pipelines?

            policy_pipelines.all? { |policy_pipeline| policy_pipeline.no_pipeline_allowed?(current_user&.id) }
          end

          def policy_stages_higher_precedence?
            policies.all? { |policy| policy.experiment_enabled?(:pipeline_execution_policy_stages_higher_precedence) }
          end

          def has_overriding_execution_policy_pipelines?
            policies.any?(&:strategy_override_project_ci?)
          end

          def overridden_pipeline_metadata
            return {} unless applying_config_override?

            metadata = policy_pipelines
              .select(&:strategy_override_project_ci?)
              .filter_map { |policy_pipeline| policy_pipeline.pipeline.pipeline_metadata }
            return {} if metadata.blank?

            # If multiple policies define the name, take the lowest in the hierarchy (project over group)
            { name: metadata.filter_map(&:name).first }.compact_blank
          end

          def applying_config_override?
            has_overriding_execution_policy_pipelines? && creating_project_pipeline?
          end

          def collect_declared_stages!(new_stages)
            return unless creating_policy_pipeline?

            if current_policy.strategy_override_project_ci?
              collect_declared_override_stages!(new_stages)
            elsif current_policy.strategy_inject_policy?
              @injected_policy_stages << new_stages
            end
          end

          def has_override_stages?
            # Stages collected from all `override_project_ci` policies that are applied on the main pipeline.
            override_policy_stages.present?
          end

          def has_injected_stages?
            # The stages are applied on the main pipeline based on all policy pipelines.
            injected_policy_stages.present?
          end

          # We inject policy stages only when;
          # - creating_policy_pipeline?: This is a temporary pipeline creation mode.
          #   We need to inject these stages for the validation because the policy may use them.
          # - has_execution_policy_pipelines?: This is the actual pipeline creation mode.
          #   It means that the result pipeline will have PEPs.
          #   We need to inject these stages because some of the policies may use them.
          # - this is a scheduled PEP pipeline
          def inject_policy_stages?
            creating_policy_pipeline? || has_execution_policy_pipelines? || scheduled_execution_policy_pipeline?
          end

          def valid_stage?(stage)
            return true if creating_policy_pipeline? || scheduled_execution_policy_pipeline?

            ::Gitlab::Ci::Config::Stages::RESERVED.exclude?(stage)
          end

          def enforce_stages!(config:)
            return config unless inject_policy_stages?

            config = ::Gitlab::Ci::Config::Stages.new(config).inject_reserved_stages!
            return config if creating_policy_pipeline?

            config[:stages] = override_policy_stages if has_override_stages?

            if has_injected_stages?
              config[:stages] =
                ::Gitlab::Ci::Config::StagesMerger.inject(
                  config[:stages],
                  injected_policy_stages,
                  strategy: policy_stages_higher_precedence? ? :original_stages_last : :original_stages_first)
            end

            config
          rescue ::Gitlab::Ci::Config::StagesMerger::InvalidStageConditionError => e
            raise e, 'Pipeline execution policy error: Cyclic dependencies detected when enforcing policies. ' \
              'Ensure stages across the project and policies are aligned.'
          end

          def job_options
            return unless creating_policy_pipeline? || scheduled_execution_policy_pipeline?

            {
              pipeline_execution_policy_job: true,
              name: current_policy.name,
              variables_override: current_policy.variables_override_strategy,
              project_id: current_policy.policy_project_id,
              sha: current_policy.policy_sha
            }.compact_blank
          end

          def target_project
            project
          end

          private

          attr_reader :project, :current_policy, :source, :current_user, :ref, :sha_context,
            :variables_attributes, :chat_data, :merge_request, :schedule, :trigger, :is_parent_pipeline_policy

          def policies
            return [] if Enums::Ci::Pipeline.gitlab_controlled_sources.key?(source)
            return project_policies unless source == :parent_pipeline
            return policies_with_child_pipeline_enforcement_enabled unless is_parent_pipeline_policy

            []
          end
          strong_memoize_attr :policies

          def project_policies
            ::Gitlab::Security::Orchestration::ProjectPipelineExecutionPolicies.new(project).configs
          end
          strong_memoize_attr :project_policies

          def policies_with_child_pipeline_enforcement_enabled
            project_policies.select(&:enforce_on_child_pipelines?)
          end
          strong_memoize_attr :policies_with_child_pipeline_enforcement_enabled

          def create_pipeline(policy, partition_id)
            result = nil
            callback = ->(duration) { log_compile_cost(result, duration) }

            measure(HISTOGRAMS.fetch(:single_pipeline), callback: callback) do
              with_policy_context(policy) do
                service = ::Ci::CreatePipelineService
                  .new(project, current_user,
                    ref: ref,
                    before: sha_context.before,
                    after: sha_context.after,
                    source_sha: sha_context.source,
                    checkout_sha: sha_context.checkout,
                    target_sha: sha_context.target,
                    partition_id: partition_id,
                    variables_attributes: variables_attributes,
                    chat_data: chat_data
                  )
                response = service.execute(source,
                  content: policy.content,
                  pipeline_policy_context: @context, # propagates parent context inside the policy pipeline creation
                  merge_request: merge_request, # This is for supporting merge request pipelines,
                  schedule: schedule,
                  trigger: trigger,
                  ignore_skip_ci: true # We can exit early from `Chain::Skip` by setting this parameter
                  # Additional parameters will be added in https://gitlab.com/gitlab-org/gitlab/-/issues/462004
                )
                result = PolicyPipelineCreationResult.new(
                  response: response,
                  job_name_mappings: service.yaml_processor_result&.job_name_mappings || {},
                  job_count: (service.yaml_processor_result&.jobs || {}).size
                )
              end
            end
          end

          def log_compile_cost(result, duration)
            return unless compile_cost_above_threshold?(result, duration)

            ::Gitlab::AppJsonLogger.info(
              build_structured_payload_labkit(
                message: 'Pipeline execution policy compile exceeded threshold',
                ::Labkit::Fields::GL_PROJECT_ID => project.id,
                pipeline_source: source,
                policy_count: policies.size,
                job_count: result.job_count,
                ::Labkit::Fields::DURATION_S => duration
              )
            )
          rescue StandardError => e
            # Runs inside pipeline creation: logging must never break it.
            ::Gitlab::ErrorTracking.track_exception(e, project_id: project.id)
          end

          def compile_cost_above_threshold?(result, duration)
            duration >= COMPILE_COST_LOG_DURATION_THRESHOLD_SECONDS ||
              result.job_count.to_i >= COMPILE_COST_LOG_JOBS_THRESHOLD
          end

          # We are setting `@current_policy` to the policy we're currently building the pipeline for.
          # By passing this context into the policy pipeline creation, we can evaluate policy-specific logic from within
          # `CreatePipelineService` by delegating to this object.
          # For example, it allows us to collect declared stages if @current_policy is `override_project_ci`.
          def with_policy_context(policy)
            @current_policy = policy
            yield.tap do
              @current_policy = nil
            end
          end

          def collect_declared_override_stages!(new_stages)
            error = OverrideStagesConflictError.new(
              "Policy `#{current_policy.name}` could not be applied. " \
                "Its stages are incompatible with stages of another `override_project_ci` policy: " \
                "#{override_policy_stages.join(', ')}.")

            if new_stages.size > override_policy_stages.size
              raise error unless stages_compatible?(override_policy_stages, new_stages)

              @override_policy_stages = new_stages
            else
              raise error unless stages_compatible?(new_stages, override_policy_stages)
            end
          end

          # `stages` are considered compatible if they are an ordered subset of `target_stages`.
          # `target_stages` is larger or equally large set of stages.
          # Elements of `stages` must appear in the same order as in `target_stages`.
          # Valid example:
          #   `stages`: [build, deploy]
          #   `target_stages`: [build, test, deploy]
          # Invalid example:
          #   `stages`: [deploy, build]
          #   `target_stages`: [build, test, deploy]
          def stages_compatible?(stages, target_stages)
            stages == target_stages & stages
          end

          def should_apply_to_empty_pipeline?(policy_pipeline, pipeline)
            apply_on_empty_pipeline = policy_apply_on_empty_pipeline(policy_pipeline)

            case apply_on_empty_pipeline
            when APPLY_ON_EMPTY_PIPELINE_ALWAYS
              true
            when APPLY_ON_EMPTY_PIPELINE_NEVER
              false
            when APPLY_ON_EMPTY_PIPELINE_IF_NO_CONFIG
              # Only apply if we're using the fallback config source (no CI config found)
              pipeline.pipeline_execution_policy_forced? && (
                # For projects with no CI config we prefer MR pipelines over branch to avoid duplicates
                pipeline.merge_request? || (pipeline.branch? && pipeline.open_merge_requests_refs.empty?)
              )
            else
              # Unknown behavior or experiment not enabled defaults to always apply
              true
            end
          end

          def policy_apply_on_empty_pipeline(policy_pipeline)
            return unless policy_pipeline.policy_config.experiment_enabled?(:apply_on_empty_pipeline_option)

            policy_pipeline.policy_config.apply_on_empty_pipeline
          end

          delegate :measure, to: ::Security::SecurityOrchestrationPolicies::ObserveHistogramsService
        end
      end
    end
  end
end
