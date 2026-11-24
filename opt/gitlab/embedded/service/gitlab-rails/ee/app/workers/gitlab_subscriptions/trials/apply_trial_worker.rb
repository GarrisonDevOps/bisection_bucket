# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class ApplyTrialWorker
      include ApplicationWorker

      ApplyTrialError = Class.new(StandardError)

      deduplicate :until_executed
      data_consistency :always
      idempotent!
      urgency :high
      feature_category :plan_provisioning

      def perform(current_user_id, trial_user_information)
        service = GitlabSubscriptions::Trials::ApplyTrialService
                    .new(uid: current_user_id, trial_user_information: trial_user_information.deep_symbolize_keys)
        result = service.execute

        return if result.success?

        logger.error(
          structured_payload(
            params: { uid: current_user_id, trial_user_information: trial_user_information },
            message: result.errors
          )
        )

        raise ApplyTrialError if service.valid_to_generate_trial?
      end
    end
  end
end
