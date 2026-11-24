# frozen_string_literal: true

module API
  module Entities
    module WorkItems
      module Features
        class Development < Grape::Entity
          # Only the count is exposed for now. The listing page renders a "closing merge requests" icon from this
          # number. The full closing merge request list is tracked separately in
          # https://gitlab.com/gitlab-org/gitlab/-/issues/601071.
          expose :closing_merge_requests_count,
            documentation: {
              type: 'Integer', example: 2,
              desc: 'Number of merge requests, in any state, that close the work item when merged. Excludes merge ' \
                'requests in projects where merge requests are disabled or private, unless the current user has ' \
                'at least the Reporter role there.'
            } do |feature, options|
            options.dig(:closing_merge_requests_counts, feature.work_item.id) || 0
          end

          # Computed by MergeRequestIssue.auto_close_issue_ids without a visibility filter, to match GraphQL's
          # willAutoCloseByMergeRequest, so it can be true even if closing_merge_requests_count is 0.
          expose :will_auto_close_by_merge_request,
            documentation: {
              type: 'Boolean', example: false,
              desc: 'Whether merging an open merge request closes the work item. True if the work item is ' \
                'open, belongs to a project that closes referenced issues automatically, and has at least one ' \
                'open closing merge request, even one the current user cannot see. Can be `true` when ' \
                '`closing_merge_requests_count` is 0.'
            } do |feature, options|
            options[:will_auto_close_ids]&.include?(feature.work_item.id) || false
          end
        end
      end
    end
  end
end
