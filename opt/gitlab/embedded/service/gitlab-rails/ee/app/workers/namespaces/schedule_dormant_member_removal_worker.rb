# frozen_string_literal: true

module Namespaces
  class ScheduleDormantMemberRemovalWorker
    include ApplicationWorker
    include CronjobQueue # rubocop:disable Scalability/CronWorkerContext -- LimitedCapacity worker scheduler

    feature_category :seat_cost_management
    data_consistency :sticky
    urgency :low

    idempotent!

    def perform
      return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

      Namespaces::RemoveDormantMembersWorker.perform_with_capacity
    end
  end
end
