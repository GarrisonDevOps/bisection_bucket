# frozen_string_literal: true

module Security
  module PipelineExecutionPolicies
    # Lists the prefill variables of the pipeline execution policies that apply to the project, as the viewer.
    class PrefillVariablesService
      # One budget for all policies, so compiling many cannot outlive the reactive cache lease.
      TIMEOUT = 30.seconds

      def initialize(project:, current_user:, sha:, ref:)
        @project = project
        @current_user = current_user
        @sha = sha
        @ref = ref
      end

      def execute
        # Checked between policies, so the last compilation can overrun the budget by its own Config timeout.
        deadline = ::Gitlab::Metrics::System.monotonic_time + TIMEOUT

        policies_by_precedence.each_with_object({}) do |policy, variables|
          if ::Gitlab::Metrics::System.monotonic_time >= deadline
            log_skipped_policy(policy, 'budget exceeded')
            break variables
          end

          variables.reverse_merge!(policy_variables(policy))
        end
      end

      private

      attr_reader :project, :current_user, :sha, :ref

      # `configs` lists the highest-precedence policy last; start from it so a spent budget drops the lowest.
      def policies_by_precedence
        ::Gitlab::Security::Orchestration::ProjectPipelineExecutionPolicies.new(project).configs.reverse
      end

      # Compiled as the viewer in the policy pipeline context, so includes are authorized exactly as in the
      # viewer's own policy pipeline. Variables stored on the policy were analyzed as another user.
      def policy_variables(policy)
        config = ::Gitlab::Ci::Config.new(policy.content, project: project, user: current_user, sha: sha, ref: ref,
          source: :web, pipeline_policy_context: context_for(policy))

        unless config.valid?
          log_skipped_policy(policy, config.errors.first)
          return {}
        end

        config.variables_with_prefill_data.select { |_name, data| data.key?(:description) }
      rescue ::Gitlab::Ci::Config::ConfigError => e
        log_skipped_policy(policy, e.message)
        {}
      end

      def context_for(policy)
        ::Gitlab::Ci::Pipeline::ExecutionPolicies::PipelineContext.new(
          project: project, current_user: current_user,
          pipeline_execution_policy_context_block: ->(args) { args.merge(current_policy: policy) }
        )
      end

      def log_skipped_policy(policy, reason)
        ::Gitlab::AppJsonLogger.warn(
          ::Labkit::Fields::LOG_MESSAGE => "Pipeline execution policy variables skipped: #{reason}",
          ::Labkit::Fields::GL_PROJECT_ID => project.id, ::Labkit::Fields::GL_USER_ID => current_user.id,
          policy_name: policy.name)
      end
    end
  end
end
