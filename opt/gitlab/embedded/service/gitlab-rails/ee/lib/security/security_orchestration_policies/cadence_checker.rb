# frozen_string_literal: true

module Security
  module SecurityOrchestrationPolicies
    module CadenceChecker
      VALID_CADENCE = /^((\*|\d{1,2})\s){2}(.+\s?){3}$/

      def valid_cadence?(cadence)
        return false if cadence == '* * * * *'

        cadence.match?(VALID_CADENCE)
      end

      def log_invalid_cadence_error(project_id, cadence)
        Gitlab::AppJsonLogger.info(event: 'scheduled_scan_execution_policy_validation',
          message: 'Invalid cadence',
          project_id: project_id,
          cadence: cadence)
      end
    end
  end
end
