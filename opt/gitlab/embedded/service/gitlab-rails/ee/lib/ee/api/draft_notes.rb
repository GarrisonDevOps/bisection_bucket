# frozen_string_literal: true

module EE
  module API
    module DraftNotes
      extend ActiveSupport::Concern

      prepended do
        helpers do
          extend ::Gitlab::Utils::Override

          override :clear_requested_changes_on_review
          def clear_requested_changes_on_review(mr)
            result = ::MergeRequests::DestroyRequestedChangesService
              .new(project: user_project, current_user: current_user)
              .execute(mr)

            return if result[:status] == :success

            # Clearing is best-effort on this path: a clean re-review with nothing to clear,
            # or the feature being unavailable, are expected and must not fail the publish.
            # Record anything unexpected (e.g. a permission failure) rather than discard it.
            ::Gitlab::AppLogger.warn(
              message: "bulk_publish reviewed: requested changes not cleared (#{result[:message]})",
              merge_request_id: mr.id
            )
          end
        end
      end
    end
  end
end
