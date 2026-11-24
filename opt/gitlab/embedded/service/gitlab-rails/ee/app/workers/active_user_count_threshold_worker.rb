# frozen_string_literal: true

class ActiveUserCountThresholdWorker # rubocop:disable Scalability/IdempotentWorker
  include ApplicationWorker

  data_consistency :always

  # rubocop:disable Scalability/CronWorkerContext
  # This worker does not perform work scoped to a context
  include CronjobQueue
  # rubocop:enable Scalability/CronWorkerContext

  feature_category :plan_provisioning

  def perform
    License.with_valid_license do |license|
      break unless license.active_user_count_threshold_reached?
      break unless license.remaining_user_count > 0

      # rubocop:disable CodeReuse/ActiveRecord
      recipients = User
        .active
        .admins
        .pluck(:email)
        .to_set
      # rubocop:enable CodeReuse/ActiveRecord

      recipients << license.licensee_email if license.licensee_email

      LicenseMailer.approaching_active_user_count_limit(recipients.to_a).deliver_later
    end
  end
end
