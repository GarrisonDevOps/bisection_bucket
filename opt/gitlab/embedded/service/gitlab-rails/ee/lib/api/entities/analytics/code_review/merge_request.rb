# frozen_string_literal: true

module API
  module Entities
    module Analytics
      module CodeReview
        class MergeRequest < ::API::Entities::MergeRequestSimple
          expose :milestone, using: ::API::Entities::Milestone
          expose :author, using: ::API::Entities::UserBasic
          expose :approved_by_users, as: :approved_by, using: ::API::Entities::UserBasic, documentation: { is_array: true }
          expose :notes_count, documentation: { type: 'Integer', example: 10 } do |mr|
            if options[:issuable_metadata]
              # Avoids an N+1 query when metadata is included
              options[:issuable_metadata][mr.id].user_notes_count
            else
              mr.notes.user.count
            end
          end
          expose :review_time, documentation: { type: 'Integer', example: 6, desc: 'Review time in hours' } do |mr|
            time = mr.metrics.review_time

            next unless time

            (time / ActiveSupport::Duration::SECONDS_PER_HOUR).floor
          end
          expose :diff_stats, documentation: { type: 'Hash' }

          private

          def diff_stats
            additions, deletions = line_counts

            result = {
              additions: additions,
              deletions: deletions,
              commits_count: object.commits_count
            }
            result[:total] = result[:additions] + result[:deletions]
            result
          end

          def line_counts
            stats = merge_request_diff_stats

            if stats
              [stats.sum(&:additions), stats.sum(&:deletions)]
            else
              # Each call to `diffs` builds a new collection, so build it once
              diff_files = object.diffs.diff_files

              [diff_files.sum(&:added_lines), diff_files.sum(&:removed_lines)]
            end
          end

          # Reads the same stats cache as the diff file collection, so no diff files are loaded.
          # The stats are empty without a merge base or when Gitaly fails, so count the diff files then.
          def merge_request_diff_stats
            return unless ::Feature.enabled?(:code_review_analytics_api_diff_stats, object.project)

            merge_request_diff = object.merge_request_diff
            stats = Gitlab::Diff::StatsCache.new(cachable_key: merge_request_diff.cache_key).read ||
              merge_request_diff.diff_stats

            stats if stats&.any? || merge_request_diff.empty?
          end
        end
      end
    end
  end
end
