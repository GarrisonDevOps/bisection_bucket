# frozen_string_literal: true

module GitlabSubscriptions
  module AddOnPurchases
    class EmailOnDuoBulkUserAssignmentsWorker # rubocop:disable Scalability/IdempotentWorker -- Don't rerun, else mass emails sending
      include ApplicationWorker

      feature_category :seat_cost_management

      data_consistency :delayed

      def perform(user_ids, email_variant)
        User.id_in(user_ids).find_each do |user|
          GitlabSubscriptions::DuoSeatAssignmentMailer.public_send(email_variant, user).deliver_later # rubocop:disable GitlabSecurity/PublicSend -- The `email_variant` argument is considered safe
        end
      end
    end
  end
end
