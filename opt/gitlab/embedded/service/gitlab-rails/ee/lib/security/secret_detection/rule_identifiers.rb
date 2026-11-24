# frozen_string_literal: true

module Security
  module SecretDetection
    module RuleIdentifiers
      GITLEAKS_TYPE = 'gitleaks_rule_id'
      GSS_TYPE      = 'gitlab_secret_scanner_rule_id'

      def self.reported_by_gss?(finding)
        finding.identifier_types.include?(GSS_TYPE)
      end
    end
  end
end
