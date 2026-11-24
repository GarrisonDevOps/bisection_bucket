# frozen_string_literal: true

module Analytics
  class RefreshCommentsData
    include MergeRequestMetricsRefresh

    class << self
      # eligible_only: skip notes that can't set first_comment_at. Not for deletes: a deleted
      # user's notes move to the ghost user, and removing one must still force a recompute.
      def for_note(note, eligible_only: false)
        merge_requests = note.merge_requests&.including_metrics
        return if merge_requests.nil?

        if eligible_only
          # Only human notes by someone other than the MR author can set first_comment_at.
          return unless note.author&.human?

          merge_requests = merge_requests.not_authored_by_user_id(note.author_id).to_a
          return if merge_requests.empty?
        end

        new(*merge_requests)
      end
    end

    private

    def metric_already_present?(metrics)
      metrics.first_comment_at
    end

    def update_metric!(metrics)
      metrics.update!(
        first_comment_at: MergeRequestMetricsCalculator.new(metrics.merge_request).first_comment_at
      )
    end
  end
end
