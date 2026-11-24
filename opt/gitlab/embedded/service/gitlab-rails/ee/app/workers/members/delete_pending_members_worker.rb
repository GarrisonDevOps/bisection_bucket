# frozen_string_literal: true

module Members
  class DeletePendingMembersWorker
    include ApplicationWorker

    feature_category :seat_cost_management
    urgency :low
    data_consistency :sticky
    idempotent!

    MAX_RUNTIME = 3.minutes
    RETRY_DELAY = 2.minutes

    def perform(group_id, deleting_user_id)
      group = Group.find_by_id(group_id)
      deleting_user = User.find_by_id(deleting_user_id)

      return unless group && deleting_user

      limiter = ::Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)

      ::Member.awaiting.or(::Member.invite).in_hierarchy(group).find_each do |member|
        ::Members::DestroyService.new(member, current_user: deleting_user, skip_subresources: true).execute

        if limiter.over_time?
          self.class.perform_in(RETRY_DELAY, group_id, deleting_user_id)
          break
        end
      end
    rescue ::Gitlab::Access::AccessDeniedError => e
      Gitlab::ErrorTracking.log_exception(e)
    end
  end
end
