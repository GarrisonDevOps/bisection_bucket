# frozen_string_literal: true

module Users
  class NotifyDormantUserBlockedWorker
    include ApplicationWorker

    data_consistency :delayed
    feature_category :seat_cost_management
    urgency :low
    defer_on_database_health_signal :gitlab_main, [:users, :members], 1.minute

    # Marked idempotent for retry safety
    # A retry will re-enqueue mailers for already-processed recipients
    idempotent!

    def perform(user_id)
      user = User.find_by_id(user_id)
      return if user.nil?
      return unless user.blocked_pending_approval?

      if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
        group = user.enterprise_group
        return unless group

        group.owners.find_each do |owner|
          ::Notify.dormant_user_blocked_on_reactivation(owner.id, user.id, group.id).deliver_later
        end
      else
        ::User.admins.active.find_each do |admin|
          ::Notify.dormant_user_blocked_on_reactivation(admin.id, user.id).deliver_later
        end
      end
    end
  end
end
