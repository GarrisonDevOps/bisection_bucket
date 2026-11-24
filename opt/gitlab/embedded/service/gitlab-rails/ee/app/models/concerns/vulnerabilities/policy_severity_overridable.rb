# frozen_string_literal: true

module Vulnerabilities
  module PolicySeverityOverridable
    extend ActiveSupport::Concern

    included do
      # Property is preloaded via `preload_severity_override_checks!` to indicate
      # the severity that will be automatically applied after merge by a severity override policy.
      # Returns nil if no policy matches.
      attr_accessor :auto_severity_override
    end

    class_methods do
      def preload_severity_override_checks!(project, findings)
        return findings if findings.empty?
        return findings unless ::Security::PolicyAvailability.any_available?(project)

        checker = Security::Findings::PolicySeverityOverrideChecker.new(project)
        return findings unless checker.policies_present?

        findings.each do |finding|
          result = checker.check_with_policy(finding)
          finding.auto_severity_override = result[:severity] if result
        end

        findings
      end
    end
  end
end
