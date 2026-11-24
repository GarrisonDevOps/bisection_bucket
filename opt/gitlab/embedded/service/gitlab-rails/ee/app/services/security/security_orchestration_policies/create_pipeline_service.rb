# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class CreatePipelineService < ::BaseProjectService
      PIPELINE_SOURCE = :security_orchestration_policy

      def execute
        return error(s_('SecurityPolicies|Invalid or empty policy')) if ci_configs.values.all?(&:blank?)

        pipelines = {}
        error_messages = []

        if pipeline_scan_config.present?
          result = execute_pipeline_scans(pipeline_scan_config)
          pipeline_scan_pipeline = result.payload

          if pipeline_scan_pipeline.created_successfully?
            pipelines[:pipeline_scan] = pipeline_scan_pipeline
          else
            error_messages.push(pipeline_scan_pipeline.full_error_messages)
          end
        end

        if on_demand_config.present?
          result = execute_on_demand_scans(on_demand_config)

          if result.status == :success
            on_demand_pipeline = result.payload

            if on_demand_pipeline.created_successfully?
              pipelines[:on_demand] = on_demand_pipeline
            else
              error_messages.push(on_demand_pipeline.full_error_messages)
            end
          else
            error_messages.push(result.message)
          end
        end

        return error(error_messages.join(" ")) if error_messages.any?

        success(payload: pipelines)
      end

      def pipeline_scan_config
        ci_configs[:pipeline_scan]
      end

      def on_demand_config
        ci_configs[:on_demand]
      end

      private

      def ci_configs
        @ci_configs ||= prepare_ci_configurations(params[:actions])
      end

      def prepare_ci_configurations(actions)
        context = Gitlab::Ci::Config::External::Context.new(project: project, user: current_user)

        ::Security::SecurityOrchestrationPolicies::ScanPipelineService.new(context,
          branch: params[:branch], pipeline_source: PIPELINE_SOURCE).execute(actions)
      end

      def execute_pipeline_scans(ci_config)
        return if ci_config.blank?

        service = Ci::CreatePipelineService.new(project, current_user, ref: params[:branch])
        service.execute(PIPELINE_SOURCE,
          content: ci_config.to_yaml,
          scan_execution_policy_context_block: policy_context_block,
          ignore_skip_ci: true)
      end

      def execute_on_demand_scans(ci_config)
        return if ci_config.blank?

        ci_config[:stages] = on_demand_stages

        service = ::AppSec::Dast::Scans::RunService.new(project, current_user)
        service.execute(
          branch: params[:branch],
          ci_configuration: ci_config.to_yaml,
          scan_execution_policy_context_block: policy_context_block
        )
      end

      def policy_context_block
        ->(args) { args.merge(policy_name: params[:policy_name], scan_variables_map: ci_configs[:variables]) }
      end

      def on_demand_stages
        [*Gitlab::Ci::Config::Entry::Stages.default,
          AppSec::Dast::ScanConfigs::BuildService::STAGE_NAME]
      end
    end
  end
end
