# frozen_string_literal: true

module Security
  module SecretDetection
    module Scanners
      GITLEAKS = :gitleaks_scanner
      GSS      = :gss_scanner
      ALL      = [GITLEAKS, GSS].freeze

      def self.target_for_finding(finding)
        return GSS if RuleIdentifiers.reported_by_gss?(finding)

        GITLEAKS
      end
    end
  end
end
