# frozen_string_literal: true

module Vulnerabilities
  module PolicyAutoDismissable
    extend ActiveSupport::Concern

    included do
      # Property is preloaded via `preload_auto_dismissal_checks` to indicate if it matches an auto-dismiss policy
      attr_accessor :matches_auto_dismiss_policy

      alias_method :matches_auto_dismiss_policy?, :matches_auto_dismiss_policy
    end

    class_methods do
      def preload_auto_dismissal_checks!(project, findings)
        return findings if findings.empty?
        return findings unless ::Security::PolicyAvailability.any_available?(project)

        checker = Security::Findings::PolicyAutoDismissalChecker.new(project)
        auto_dismissal_map = checker.check_batch(findings)

        findings.each do |finding|
          finding.matches_auto_dismiss_policy = auto_dismissal_map.fetch(finding.uuid, false)
        end

        findings
      end
    end
  end
end
