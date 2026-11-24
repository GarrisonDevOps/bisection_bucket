# frozen_string_literal: true

module Projects
  module ImportExport
    class LinkMergeRequestHeadPipelinesService
      BATCH_SIZE = 100

      def initialize(project)
        @project = project
      end

      # Walks the project's merge requests by iid, starting after `cursor`.
      # Stops when `limiter` is over time and returns the iid to resume from.
      def execute(limiter, cursor: nil)
        next_cursor = nil

        merge_requests_after(cursor).each_batch(of: BATCH_SIZE, column: :iid) do |batch|
          link_head_pipelines(batch)
          next unless limiter.over_time?

          next_cursor = batch.maximum(:iid)
          break
        end

        ServiceResponse.success(payload: { completed: next_cursor.nil?, cursor: next_cursor })
      end

      private

      attr_reader :project

      def link_head_pipelines(batch)
        with_possible_head_pipeline(without_head_pipeline(batch)).each(&:update_head_pipeline)
      end

      # rubocop:disable CodeReuse/ActiveRecord -- queries only used by this import service
      def merge_requests_after(cursor)
        relation = project.merge_requests
        relation = relation.where(MergeRequest.arel_table[:iid].gt(cursor)) if cursor
        relation
      end

      def without_head_pipeline(batch)
        batch.where(head_pipeline_id: nil).preload(:latest_merge_request_diff, :source_project).to_a
      end

      # Drops merge requests that `MergeRequest#find_diff_head_pipeline` can't match: it needs a pipeline
      # for the merge request, or a pipeline in the source project on the diff head sha.
      def with_possible_head_pipeline(records)
        # A nil SHA would match any pipeline that has no source_sha
        records = records.select { |merge_request| merge_request.diff_head_sha.present? }
        return [] if records.empty?

        with_pipeline = ::Ci::Pipeline
          .where(merge_request_id: records.map(&:id))
          .distinct
          .limit(records.size)
          .pluck(:merge_request_id)
          .to_set

        source_project_ids = records.map(&:source_project_id).uniq
        diff_head_shas = records.map(&:diff_head_sha).uniq

        branch_pipelines = ::Ci::Pipeline
          .for_project(source_project_ids)
          .for_sha(diff_head_shas)
          .distinct
          # Each sha matches at most once per source project
          .limit(source_project_ids.size * diff_head_shas.size)
          .pluck(:project_id, :sha)
          .to_set

        records.select do |merge_request|
          with_pipeline.include?(merge_request.id) ||
            branch_pipelines.include?([merge_request.source_project_id, merge_request.diff_head_sha])
        end
      end
      # rubocop:enable CodeReuse/ActiveRecord
    end
  end
end
