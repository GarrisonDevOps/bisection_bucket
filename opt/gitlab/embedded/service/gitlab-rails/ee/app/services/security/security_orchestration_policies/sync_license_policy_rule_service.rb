# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class SyncLicensePolicyRuleService
      include Gitlab::Utils::StrongMemoize

      def initialize(project:, security_policy:, approval_policy_rule:, scan_result_policy_read:)
        @project = project
        @security_policy = security_policy
        @approval_policy_rule = approval_policy_rule
        @scan_result_policy_read = scan_result_policy_read
      end

      def execute
        security_policy.delete_software_license_policies_for_project(
          project, security_policy.approval_policy_rules.id_in(approval_policy_rule.id)
        )

        create_software_license_policies
      end

      private

      attr_accessor :project, :security_policy, :approval_policy_rule, :scan_result_policy_read

      def create_software_license_policies
        create_software_license_params.each do |params|
          ::SoftwareLicensePolicies::CreateService.new(project, author, params).execute
        end
      end

      def create_software_license_params
        if rule_content[:license_types].present?
          software_license_params_for_license_types
        elsif rule_content[:licenses].present?
          software_license_params_for_licenses
        else
          []
        end
      end

      def software_license_params_for_license_types
        rule_content[:license_types].map do |license_type|
          approval_status = rule_content[:match_on_inclusion_license] ? 'denied' : 'allowed'
          software_license_params(license_type, approval_status)
        end
      end

      def software_license_params_for_licenses
        denied_licenses_params + allowed_licenses_params
      end

      def denied_licenses_params
        denied_licenses = rule_content_licenses.fetch(:denied, [])

        denied_licenses.map do |license|
          software_license_params(license[:name], 'denied')
        end
      end

      def allowed_licenses_params
        allowed_licenses = rule_content_licenses.fetch(:allowed, [])

        allowed_licenses.map do |license|
          software_license_params(license[:name], 'allowed')
        end
      end

      def software_license_params(name, approval_status)
        {
          name: name,
          approval_status: approval_status,
          approval_policy_rule_id: approval_policy_rule.id,
          scan_result_policy_read: scan_result_policy_read
        }
      end

      def author
        security_policy.security_orchestration_policy_configuration.policy_last_updated_by
      end

      def rule_content
        approval_policy_rule.content.deep_symbolize_keys
      end
      strong_memoize_attr :rule_content

      def rule_content_licenses
        rule_content[:licenses]
      end
      strong_memoize_attr :rule_content_licenses
    end
  end
end
