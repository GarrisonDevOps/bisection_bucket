# frozen_string_literal: true

module Security
  module Findings
    class PolicyAutoDismissalChecker
      include Gitlab::Utils::StrongMemoize

      def initialize(project)
        @project = project
      end

      def check(finding)
        rules.any? { |rule| rule.match?(finding) }
      end

      def check_batch(findings)
        return {} if policies.empty?

        findings.each_with_object({}) do |finding, result|
          result[finding.uuid] = check(finding)
        end
      end

      private

      attr_reader :project

      def policies
        return [] unless ::Security::PolicyAvailability.any_available?(project)

        project
          .vulnerability_management_policies
          .auto_dismiss_policies.including_rules
      end
      strong_memoize_attr :policies

      def rules
        policies
          .flat_map(&:vulnerability_management_policy_rules)
          .select(&:type_detected?)
      end
      strong_memoize_attr :rules
    end
  end
end
