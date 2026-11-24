# frozen_string_literal: true

module Onboarding
  module SelfManaged
    class CreateWelcomeProductInteractionWorker
      include ApplicationWorker

      deduplicate :until_executed
      data_consistency :delayed

      idempotent!
      # This worker calls CreateWelcomeProductInteractionService, which POSTs
      # to the subscription portal via Client.opt_in_lead.
      worker_has_external_dependencies!

      feature_category :onboarding

      def perform(user_id)
        user = User.find_by_id(user_id)
        return unless user

        result = ::Onboarding::SelfManaged::CreateWelcomeProductInteractionService.new(user: user).execute
        return if result.success?

        logger.error(
          structured_payload(
            message: result.message.to_s,
            user_id: user_id
          )
        )
      end
    end
  end
end
