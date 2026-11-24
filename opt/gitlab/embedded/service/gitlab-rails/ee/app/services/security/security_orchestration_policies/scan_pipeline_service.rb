# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class ScanPipelineService
      include Gitlab::Loggable
      include ::Gitlab::Utils::StrongMemoize

      EMPTY_RESULT = { pipeline_scan: {}, on_demand: {}, variables: {} }.freeze
      HISTOGRAM = :gitlab_security_policies_scan_execution_configuration_rendering_seconds
      TOP_LEVEL_VARIABLES = { GITLAB_SCAN_EXECUTION_POLICY_PIPELINE: 'true' }.freeze

      attr_reader :project, :base_variables, :branch, :context, :template_cache, :job_name_suffix

      def initialize(context, branch: nil, pipeline_source: nil, job_name_suffix: nil)
        @project = context.project
        @context = context
        @branch = branch
        @template_cache = TemplateCacheService.new
        @pipeline_source = pipeline_source
        @job_name_suffix = job_name_suffix
      end

      def execute(actions)
        return EMPTY_RESULT if actions.empty?

        measure(HISTOGRAM, callback: ->(duration) { log_duration(duration, actions.size) }) do
          prepare_base_variables(actions)

          actions = actions.select do |action|
            valid_scan_type?(action[:scan]) && pipeline_scan_type?(action[:scan].to_s)
          end

          on_demand_scan_actions, other_actions = actions.partition do |action|
            on_demand_scan_type?(action[:scan].to_s)
          end

          pipeline_scan_configs = other_actions.map.with_index do |action, index|
            prepare_policy_configuration(action, index)
          end

          on_demand_configs = prepare_on_demand_policy_configuration(on_demand_scan_actions)

          pipeline_variables = collect_config_variables(other_actions, pipeline_scan_configs)
          on_demand_variables = collect_config_variables(on_demand_scan_actions, on_demand_configs)
          variables = pipeline_variables.merge(on_demand_variables)

          { pipeline_scan: scan_config(pipeline_scan_configs),
            on_demand: scan_config(on_demand_configs),
            variables: variables }
        end
      end

      private

      def scan_config(configs)
        return {} if configs.empty?

        configs
          .reduce({}, :merge)
          .merge(variables: TOP_LEVEL_VARIABLES)
      end

      def collect_config_variables(actions, configs)
        actions.zip(configs).each_with_object({}) do |(action, config), hash|
          variables = scan_variables_with_action_variables(action)

          config&.each_key do |key|
            hash[key] = variables
          end
        end
      end

      def pipeline_scan_type?(scan_type)
        scan_type.in?(Security::ScanExecutionPolicy::PIPELINE_SCAN_TYPES)
      end

      def on_demand_scan_type?(scan_type)
        scan_type.in?(Security::ScanExecutionPolicy::ON_DEMAND_SCANS)
      end

      def valid_scan_type?(scan_type)
        Security::ScanExecutionPolicy.valid_scan_type?(scan_type)
      end

      def prepare_on_demand_policy_configuration(actions)
        return {} if actions.blank?

        Security::SecurityOrchestrationPolicies::OnDemandScanPipelineConfigurationService
          .new(project)
          .execute(actions)
      end

      def prepare_policy_configuration(action, index)
        variables = scan_variables_with_action_variables(action)
        inputs = action[:inputs].is_a?(Hash) ? action[:inputs] : {}

        ::Security::SecurityOrchestrationPolicies::CiConfigurationService
          .new(project: project, params: {
            template_cache: template_cache, job_name_suffix: job_name_suffix, inputs: inputs
          })
          .execute(action, variables, context, index)
          .deep_symbolize_keys
      end

      def scan_variables(action)
        base_variables[action[:scan].to_sym].to_h
      end

      def action_variables(action)
        action[:variables].to_h.stringify_keys
      end

      def scan_variables_with_action_variables(action)
        scan_variables(action).merge(action_variables(action))
      end

      def log_duration(duration, action_count)
        Gitlab::AppJsonLogger.debug(
          build_structured_payload(
            duration: duration,
            project_id: project.id,
            action_count: action_count))
      end

      def prepare_base_variables(actions)
        @base_variables = ::Security::ScanExecutionPolicy::Config::SCAN_VARIABLES_WITH_RESTRICTED_VARIABLES
          .deep_merge(secret_detection_variables(actions))
      end

      def security_orchestration_policy?
        @pipeline_source == :security_orchestration_policy
      end

      def secret_detection_variables(actions)
        return {} unless security_orchestration_policy?
        return {} unless actions.detect { |a| a[:scan] == 'secret_detection' }

        unless last_scan_commit_sha.present? && most_recent_commit_sha.present?
          return { secret_detection: { 'SECRET_DETECTION_HISTORIC_SCAN' => 'true' } }
        end

        # if the actions has the SECRET_DETECTION_HISTORIC_SCAN variable set to true, we don't want to set
        # the SECRET_DETECTION_LOG_OPTIONS
        return {} if actions.detect { |a| a.dig(:variables, :SECRET_DETECTION_HISTORIC_SCAN) == 'true' }

        { secret_detection: { 'SECRET_DETECTION_LOG_OPTIONS' => commit_range } }
      end

      def last_scan_commit_sha
        Ci::Pipeline.order_id_desc
                    .for_project(project).for_ref(branch)
                    .with_pipeline_source(:security_orchestration_policy)
                    .find_by_id(pipeline_ids)&.sha
      end
      strong_memoize_attr :last_scan_commit_sha

      def pipeline_ids
        Security::Scan.pipeline_ids(project, 'secret_detection')
      end

      def most_recent_commit_sha
        project.repository.commit(branch)&.sha
      end
      strong_memoize_attr :most_recent_commit_sha

      def commit_range
        "#{last_scan_commit_sha}..#{most_recent_commit_sha}"
      end

      delegate :measure, to: Security::SecurityOrchestrationPolicies::ObserveHistogramsService
    end
  end
end
