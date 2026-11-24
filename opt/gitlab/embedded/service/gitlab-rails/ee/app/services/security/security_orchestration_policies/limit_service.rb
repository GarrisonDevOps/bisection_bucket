# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    class LimitService < BaseContainerService
      DEFAULT_LIMITS = {
        pipeline_execution_policies: {
          configuration: 5,
          pipeline: 5
        },
        scan_execution_policies: {
          configuration: 5
        },
        approval_policies: {
          configuration: 5
        },
        vulnerability_management_policies: {
          configuration: 5
        },
        dependency_firewall_policies: {
          configuration: 5
        }
      }.freeze

      def pipeline_execution_policies_per_configuration_limit
        per_configuration_limit_for_policy_type(:pipeline_execution_policies)
      end

      def scan_execution_policies_per_configuration_limit
        per_configuration_limit_for_policy_type(:scan_execution_policies)
      end

      def approval_policies_per_configuration_limit
        per_configuration_limit_for_policy_type(:approval_policies)
      end

      def vulnerability_management_policies_per_configuration_limit
        per_configuration_limit_for_policy_type(:vulnerability_management_policies)
      end

      def dependency_firewall_policies_per_configuration_limit
        per_configuration_limit_for_policy_type(:dependency_firewall_policies)
      end

      def pipeline_execution_policies_per_pipeline_limit
        DEFAULT_LIMITS.dig(:pipeline_execution_policies, :pipeline)
      end

      private

      attr_reader :container

      delegate :root_ancestor, to: :container, allow_nil: true

      def per_configuration_limit_for_policy_type(policy_type)
        root_namespace_limit_for_policy_type(policy_type).presence ||
          application_setting_per_configuration_limit_for_policy_type(policy_type).presence ||
          DEFAULT_LIMITS.dig(policy_type, :configuration)
      end

      # rubocop:disable Metrics/CyclomaticComplexity -- flat branching for policy type mapping
      def root_namespace_limit_for_policy_type(policy_type)
        return if root_ancestor.nil?

        # This switch ladder is tested in limit_service_spec.rb but not detected by coverage
        # rubocop:disable Gitlab/NoCodeCoverageComment -- Fully tested in EE and tested in Foss through feature specs in spec/features/invites_spec.rb
        # simplecov:disable
        limit = case policy_type
                when :pipeline_execution_policies
                  root_ancestor&.pipeline_execution_policies_per_configuration_limit
                when :scan_execution_policies
                  root_ancestor&.scan_execution_policies_per_configuration_limit
                when :approval_policies
                  root_ancestor&.approval_policies_per_configuration_limit
                when :vulnerability_management_policies
                  root_ancestor&.vulnerability_management_policies_per_configuration_limit
                when :dependency_firewall_policies
                  root_ancestor&.dependency_firewall_policies_per_configuration_limit
                end
        # rubocop:enable Metrics/CyclomaticComplexity
        # simplecov:enable
        # rubocop:enable Gitlab/NoCodeCoverageComment

        return if limit&.zero?

        limit
      end

      def application_setting_per_configuration_limit_for_policy_type(policy_type)
        case policy_type
        when :pipeline_execution_policies
          Gitlab::CurrentSettings.pipeline_execution_policies_per_configuration_limit
        when :scan_execution_policies
          Gitlab::CurrentSettings.scan_execution_policies_per_configuration_limit
        when :approval_policies
          Gitlab::CurrentSettings.security_approval_policies_limit
        when :vulnerability_management_policies
          Gitlab::CurrentSettings.vulnerability_management_policies_per_configuration_limit
        when :dependency_firewall_policies
          Gitlab::CurrentSettings.dependency_firewall_policies_per_configuration_limit
        end
      end
    end
  end
end
