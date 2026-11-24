# frozen_string_literal: true

module Gitlab
  module EventStore
    module Subscriptions
      class GitlabSubscriptionsSubscriptions < BaseSubscriptions
        def register
          store.subscribe ::GitlabSubscriptions::MemberManagement::ApplyPendingMemberApprovalsWorker,
            to: ::Members::MembershipModifiedByAdminEvent,
            if: ->(_) {
              ::Gitlab::CurrentSettings.enable_member_promotion_management?
            }
          store.subscribe ::GitlabSubscriptions::Members::RecordLastActivityWorker,
            to: ::Users::ActivityEvent,
            if: ->(event) {
              return unless ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)

              namespace_id = event.data[:namespace_id]

              !GitlabSubscriptions::Members::ActivityService.lease_taken?(
                namespace_id, event.data[:user_id]
              )
            }
        end
      end
    end
  end
end
