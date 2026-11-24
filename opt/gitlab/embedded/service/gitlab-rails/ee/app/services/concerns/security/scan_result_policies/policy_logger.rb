# frozen_string_literal: true

module Security
  module ScanResultPolicies
    module PolicyLogger
      private

      def log_policy_evaluation(event, message, project: nil, **attributes)
        default_attributes = {
          workflow: 'approval_policy_evaluation',
          event: event,
          project_path: project&.full_path
        }.compact
        Gitlab::AppJsonLogger.info(message: message, **default_attributes.merge(attributes))
      end
    end
  end
end
