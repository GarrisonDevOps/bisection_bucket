# frozen_string_literal: true

class SetUserStatusBasedOnUserCapSettingWorker
  include ApplicationWorker

  data_consistency :always

  sidekiq_options retry: 3
  include ::Gitlab::Utils::StrongMemoize

  feature_category :user_profile

  idempotent!

  def perform(user_id)
    user = User.includes(:identities).find_by_id(user_id) # rubocop: disable CodeReuse/ActiveRecord

    return unless user.activate_based_on_user_cap?

    send_user_cap_reached_email if User.user_cap_reached?
  end

  private

  def send_user_cap_reached_email
    User.admins.active.each do |user|
      ::Notify.user_cap_reached(user.id).deliver_later
    end
  end
end
