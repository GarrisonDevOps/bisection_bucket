# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module Variables
        module Builder
          class ScanExecutionPolicies
            include ::Gitlab::Utils::StrongMemoize

            attr_reader :project, :pipeline

            def initialize(pipeline)
              @pipeline = pipeline
              @project = pipeline.project
            end

            # Returns scan execution policy variables for a job, optionally filtering out
            # variables that conflict with YAML variables in scheduled SEP pipelines.
            #
            # For scheduled SEP pipelines, skips any variables that are already defined in
            # the job's YAML variables. This prevents overriding variables that were correctly
            # calculated during pipeline creation (e.g., SECRET_DETECTION_HISTORIC_SCAN), while
            # still allowing SEP to enforce highest precedence in non-scheduled pipelines.
            #
            # @param job_name [String] The name of the job
            # @param yaml_variables [Array<Hash>] The YAML variables defined for the job (optional)
            # @return [Gitlab::Ci::Variables::Collection] Collection of policy variables
            def variables(job_name, yaml_variables = nil)
              ::Gitlab::Ci::Variables::Collection.new.tap do |variables|
                next variables unless enforce_scan_execution_policies_variables?(job_name)

                yaml_variable_keys = Array.wrap(yaml_variables).pluck(:key).to_set # rubocop:disable CodeReuse/ActiveRecord -- Array#pluck

                variables_for_job(job_name)
                  .reject { |key, _value| skip_variable?(key, yaml_variable_keys) }
                  .each { |key, value| variables.append(key: key, value: value.to_s) }
              end
            end

            private

            # Skip injecting a variable if ALL the following conditions are met:
            # 1. The pipeline is a scheduled SEP pipeline (source: security_orchestration_policy)
            # 2. The variable already exists in the job's YAML variables
            def skip_variable?(key, yaml_variable_keys)
              pipeline&.security_orchestration_policy? && yaml_variable_keys.include?(key)
            end

            def enforce_scan_execution_policies_variables?(job_name)
              return false if job_name.blank?

              project.licensed_feature_available?(:security_orchestration_policies)
            end

            def variables_for_job(job_name)
              active_scan_variables[job_name.to_sym] || []
            end

            def active_scan_variables
              ::Security::SecurityOrchestrationPolicies::ScanPipelineService
                .new(ci_context, branch: pipeline.ref, pipeline_source: pipeline.source)
                .execute(active_scan_actions)[:variables]
            end
            strong_memoize_attr :active_scan_variables

            def active_scan_actions
              ::Gitlab::Security::Orchestration::ProjectPolicyConfigurations
                .new(project)
                .all
                .flat_map { |config| fetch_active_actions(config) }
                .compact
                .uniq
            end

            def ci_context
              ::Gitlab::Ci::Config::External::Context.new(project: project)
            end

            def fetch_active_actions(config)
              config.active_policies_scan_actions_for_project(pipeline.jobs_git_ref, project, pipeline.source)
            end
          end
        end
      end
    end
  end
end
