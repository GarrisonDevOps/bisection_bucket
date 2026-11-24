# frozen_string_literal: true

module Types
  module Vulnerabilities
    class AutoRemediationStatusEnum < BaseEnum
      graphql_name 'VulnerabilityAutoRemediationStatus'
      description 'Outcome of triggering auto-remediation for a vulnerability.'

      value 'IN_PROGRESS',
        value: 'in_progress',
        description: 'Auto-remediation was triggered and a merge request will be created if a fix is produced.'

      value 'NO_FIX_AVAILABLE',
        value: 'no_fix_available',
        description: 'No fix is available for the vulnerability, so auto-remediation was not triggered.'

      value 'UNSUPPORTED',
        value: 'unsupported',
        description: 'No auto-remediation path is available for the vulnerability, so it was not triggered.'
    end
  end
end
