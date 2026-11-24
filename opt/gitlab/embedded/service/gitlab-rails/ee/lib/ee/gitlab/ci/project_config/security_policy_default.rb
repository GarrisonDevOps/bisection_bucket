# frozen_string_literal: true

module EE
  module Gitlab
    module Ci
      module ProjectConfig
        module SecurityPolicyDefault
          extend ::Gitlab::Utils::Override
          include ::Gitlab::Utils::StrongMemoize

          DUMMY_CONTENT = {
            'Pipeline execution policy trigger' => {
              'stage' => ::Gitlab::Ci::Config::Stages::EDGE_PRE,
              'script' => ['echo "Forcing project pipeline to run policy jobs."']
            }
          }.freeze

          # Scan Execution Policies is a feature that works in parallel with Pipeline Execution Policies.
          # Even if there are PEPs with `override_project_ci`, we want SEPs to still be applied.
          override :content
          def content
            # We merge the security scans with the pipeline configuration in ee/lib/ee/gitlab/ci/config_ee.rb.
            # An empty config with no content is enough to trigger the merge process when the Auto DevOps is disabled
            # and no .gitlab-ci.yml is present.
            if has_applicable_scan_execution_policies_defined?
              YAML.dump(nil)
            elsif has_pipeline_execution_policies_defined?
              # Pipeline execution policy jobs will be merged onto the project pipeline.
              # Create a dummy job to ensure that project pipeline gets created.
              YAML.dump(DUMMY_CONTENT)
            end
          end
          strong_memoize_attr :content

          override :source
          def source
            if has_applicable_scan_execution_policies_defined?
              :security_policies_default_source
            elsif has_pipeline_execution_policies_defined?
              :pipeline_execution_policy_forced
            end
          end
          strong_memoize_attr :source

          private

          attr_reader :pipeline_policy_context, :source_branch

          def has_pipeline_execution_policies_defined?
            pipeline_policy_context&.pipeline_execution_context&.has_execution_policy_pipelines?
          end

          def has_applicable_scan_execution_policies_defined?
            return false unless applicable_trigger?

            valid_pipeline_source? && security_policies_available? && active_scan_execution_policies?
          end

          def applicable_trigger?
            triggered_for_branch || triggered_for_mr_pipelines?
          end

          def triggered_for_mr_pipelines?
            pipeline_source&.to_sym == :merge_request_event
          end

          def valid_pipeline_source?
            return false if pipeline_source.blank?

            ::Enums::Ci::Pipeline.ci_and_security_orchestration_sources.key?(pipeline_source.to_sym)
          end

          def security_policies_available?
            project.licensed_feature_available?(:security_orchestration_policies)
          end

          def active_scan_execution_policies?
            applicable_policies.any?
          end

          def applicable_policies
            branch_service = ::Security::SecurityOrchestrationPolicies::PolicyBranchesService.new(project: project)

            ::Gitlab::Security::Orchestration::ProjectPolicyConfigurations
              .new(project).all
              .to_a
              .flat_map do |config|
                config.active_scan_execution_policies_for_pipelines.select do |policy|
                  policy_applicable_for_scope?(policy, config) &&
                    policy_applicable_for_pipeline_source?(policy) &&
                    policy_applicable_for_branch?(branch_service, policy)
                end
              end
          end
          strong_memoize_attr :applicable_policies

          def policy_applicable_for_scope?(policy, configuration)
            ::Security::SecurityOrchestrationPolicies::PolicyScopeChecker
              .new(project: project)
              .policy_applicable?(policy, configuration: configuration)
          end

          def policy_applicable_for_pipeline_source?(policy)
            return true if pipeline_source.blank?

            policy[:rules].any? do |rule|
              rule_pipeline_sources = rule.dig(:pipeline_sources, :including)
              rule_pipeline_sources.blank? || rule_pipeline_sources.include?(pipeline_source.to_s)
            end
          end

          def policy_applicable_for_branch?(service, policy)
            applicable_branches = service.scan_execution_branches(policy[:rules], source_branch)

            source_branch.in?(applicable_branches)
          end
        end
      end
    end
  end
end
