# frozen_string_literal: true

module Security
  module ScanExecutionPolicy
    extend ActiveSupport::Concern
    include ::Gitlab::Utils::StrongMemoize

    POLICY_TYPE_NAME = 'Scan execution policy'

    RULE_TYPES = {
      pipeline: 'pipeline',
      schedule: 'schedule'
    }.freeze

    SCAN_TYPES = %w[dast secret_detection cluster_image_scanning container_scanning sast sast_iac
      dependency_scanning].freeze
    PIPELINE_SCAN_TYPES = SCAN_TYPES.excluding("cluster_image_scanning").freeze
    ON_DEMAND_SCANS = %w[dast].freeze

    # Run as a Duo flow, not as CI jobs, so kept out of SCAN_TYPES. A subset of
    # Enums::Security::FLOW_BACKED_SCAN_TYPES: only these can be dispatched.
    AGENTIC_SCAN_TYPES = %w[business_logic].freeze

    included do
      has_many :rule_schedules,
        class_name: 'Security::OrchestrationPolicyRuleSchedule',
        foreign_key: :security_orchestration_policy_configuration_id,
        inverse_of: :security_orchestration_policy_configuration
    end

    def self.valid_scan_type?(scan_type)
      SCAN_TYPES.include?(scan_type)
    end

    def self.agentic_scan_type?(scan_type)
      AGENTIC_SCAN_TYPES.include?(scan_type.to_s)
    end

    # `business_logic` may only be used where its foundational flow is available to the container's
    # top-level group (deployment, flag, beta opt-in and Duo license) and the license includes the analyzer.
    def self.agentic_scan_available?(container)
      return false unless container

      flow = ::Ai::Catalog::FoundationalFlow.bl_security_experimental
      return false unless flow.available_for?(container.root_ancestor)

      container.licensed_feature_available?(:business_logic)
    end

    def active_scan_execution_policies
      policy_limit = limit_service.scan_execution_policies_per_configuration_limit

      scan_execution_policy.select { |config| config[:enabled] }.first(policy_limit)
    end

    def active_scan_execution_policies_for_pipelines
      active_scan_execution_policies.select do |policy|
        policy&.[](:rules)&.any? { |rule| rule&.[](:type) == RULE_TYPES[:pipeline] }
      end
    end

    def active_policy_names_with_dast_site_profile(profile_name)
      active_policy_names_with_dast_profiles.dig(:site_profiles, profile_name)
    end

    def active_policy_names_with_dast_scanner_profile(profile_name)
      active_policy_names_with_dast_profiles.dig(:scanner_profiles, profile_name)
    end

    def delete_all_schedules
      rule_schedules.delete_all(:delete_all)
    end

    def scan_execution_policy
      policy_by_type(:scan_execution_policy).map.with_index do |policy, index|
        policy.merge(type: 'scan_execution_policy', policy_index: index)
      end
    end

    def active_policies_for_project(ref, project, pipeline_source = nil)
      branch_service = Security::SecurityOrchestrationPolicies::PolicyBranchesService.new(project: project)
      scope_checker = Security::SecurityOrchestrationPolicies::PolicyScopeChecker.new(project: project)

      policies = active_scan_execution_policies
        .select { |policy| scope_checker.policy_applicable?(policy, configuration: self) }

      policies = policies.select do |policy|
        applicable_for_ref?(block_given? ? yield(policy[:rules]) : policy[:rules], ref,
          branch_service)
      end

      policies.select do |policy|
        applicable_for_pipeline_source?(block_given? ? yield(policy[:rules]) : policy[:rules],
          pipeline_source)
      end
    end

    def active_scan_execution_policy_names(ref, project)
      active_policies_for_project(ref, project).pluck(:name) # rubocop:disable Database/AvoidUsingPluckWithoutLimit -- not an ActiveRecord model and active_scan_execution_policies has limit
    end

    def active_pipeline_policies_for_project(ref, project, pipeline_source = nil)
      active_policies_for_project(ref, project, pipeline_source) do |policy_rules|
        policy_rules.select { |rule| rule[:type] == RULE_TYPES[:pipeline] }
      end
    end

    def active_policies_scan_actions_for_project(ref, project, pipeline_source = nil)
      active_policies_for_project(ref, project, pipeline_source).flat_map { |policy| policy[:actions] }
    end

    private

    def active_policy_names_with_dast_profiles
      strong_memoize(:active_policy_names_with_dast_profiles) do
        profiles = { site_profiles: Hash.new { Set.new }, scanner_profiles: Hash.new { Set.new } }

        active_scan_execution_policies.each do |policy|
          policy[:actions].each do |action|
            next unless action[:scan].in?(ON_DEMAND_SCANS)

            profiles[:site_profiles][action[:site_profile]] += [policy[:name]]
            if action[:scanner_profile].present?
              profiles[:scanner_profiles][action[:scanner_profile]] += [policy[:name]]
            end
          end
        end

        profiles
      end
    end

    def applicable_for_ref?(policy_rules, ref, service)
      return false unless Gitlab::Git.branch_ref?(ref)

      ref_name = Gitlab::Git.ref_name(ref)
      applicable_branches = service.scan_execution_branches(policy_rules, ref_name)

      ref_name.in?(applicable_branches)
    end

    def applicable_for_pipeline_source?(policy_rules, pipeline_source)
      return true if pipeline_source.blank?

      policy_rules.any? do |rule|
        rule_pipeline_sources = rule.dig(:pipeline_sources, :including)
        rule_pipeline_sources.blank? || rule_pipeline_sources.include?(pipeline_source.to_s)
      end
    end
  end
end
