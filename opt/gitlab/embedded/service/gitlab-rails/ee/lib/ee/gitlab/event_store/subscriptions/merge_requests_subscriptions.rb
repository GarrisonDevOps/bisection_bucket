# frozen_string_literal: true

module EE
  module Gitlab
    module EventStore
      module Subscriptions
        module MergeRequestsSubscriptions
          def register
            super

            store.subscribe ::MergeRequests::StreamApprovalAuditEventWorker, to: ::MergeRequests::ApprovedEvent
            store.subscribe ::MergeRequests::ApprovalMetricsEventWorker, to: ::MergeRequests::ApprovedEvent
            store.subscribe ::MergeRequests::CreateApprovalsResetNoteWorker, to: ::MergeRequests::ApprovalsResetEvent
            store.subscribe ::MergeRequests::ProcessAutoMergeFromEventWorker,
              to: ::MergeRequests::ExternalStatusCheckPassedEvent
            store.subscribe ::MergeRequests::ProcessAutoMergeFromEventWorker, to: ::MergeRequests::UnblockedStateEvent
            store.subscribe ::MergeRequests::ProcessAutoMergeFromEventWorker,
              to: ::MergeRequests::OverrideRequestedChangesStateEvent
            store.subscribe ::MergeRequests::ProcessAutoMergeFromEventWorker, to: ::MergeRequests::ApprovedEvent
            store.subscribe ::MergeRequests::ProcessAutoMergeFromEventWorker,
              to: ::MergeRequests::ViolationsUpdatedEvent,
              if: ->(event) { ::MergeRequests::ProcessAutoMergeFromEventWorker.dispatch?(event) }
            store.subscribe ::MergeRequests::RemoveUserApprovalRulesWorker,
              to: ::ProjectAuthorizations::AuthorizationsRemovedEvent
            store.subscribe ::MergeRequests::ProcessMergeAuditEventWorker, to: ::MergeRequests::MergedEvent
            store.subscribe ::MergeRequests::CleanupAiSuggestedReviewersWorker,
              to: ::MergeRequests::MergedEvent,
              if: ->(event) { ::MergeRequests::CleanupAiSuggestedReviewersWorker.dispatch?(event) }
            store.subscribe ::MergeRequests::CleanupAiSuggestedReviewersWorker,
              to: ::MergeRequests::ClosedEvent,
              if: ->(event) { ::MergeRequests::CleanupAiSuggestedReviewersWorker.dispatch?(event) }
          end
        end
      end
    end
  end
end
