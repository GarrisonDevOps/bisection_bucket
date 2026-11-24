# frozen_string_literal: true

module Security
  module ScanResultPolicies
    # Backstop for violations that no pipeline event will resolve anymore, for example
    # on merge requests the head SHA lookup misses or rows written after the merge.
    class SweepStaleRunningViolationsWorker
      include ApplicationWorker
      include Gitlab::Utils::StrongMemoize
      include CronjobQueue
      include ::Security::ScanResultPolicies::PolicyLogger

      idempotent!
      data_consistency :sticky
      deduplicate :until_executed
      feature_category :security_policy_management

      STALE_AFTER = 1.hour
      BATCH_SIZE = 100
      MAX_ROWS_PER_RUN = 1_000
      CURSOR_KEY = 'security:scan_result_policies:sweep_stale_running_violations:cursor'
      CURSOR_TTL = 1.day

      def perform
        @handled_merge_request_ids = Set.new
        @counts = Hash.new(0)

        iterator = Gitlab::Pagination::Keyset::Iterator.new(
          scope: ::Security::ScanResultPolicyViolation.running_updated_before(STALE_AFTER.ago),
          cursor: load_cursor)

        iterator.each_batch(of: BATCH_SIZE) do |batch|
          violations = batch.to_a
          @counts[:scanned] += violations.size
          sweep(violations)

          next if @counts[:scanned] < MAX_ROWS_PER_RUN

          # Rows left running (flag disabled, pipeline still running) would otherwise
          # fill every run's budget, so the next run resumes after them.
          save_cursor(violations.last)
          break
        end

        reset_cursor if @counts[:scanned] < MAX_ROWS_PER_RUN
        log_extra_metadata_on_done(:result, @counts)
      end

      private

      def sweep(violations)
        merge_request_ids = violations
          .select { |violation| enabled_for_project?(violation.project_id) }
          .map(&:merge_request_id)
          .uniq - @handled_merge_request_ids.to_a
        return if merge_request_ids.empty?

        @handled_merge_request_ids.merge(merge_request_ids)

        ::MergeRequest.id_in(merge_request_ids).including_target_project.each do |merge_request|
          with_context(project: merge_request.target_project) { sweep_merge_request(merge_request) }
        end
      end

      def sweep_merge_request(merge_request)
        return unless ::Security::PolicyAvailability.any_available?(merge_request.target_project)

        if merge_request.merged? || merge_request.closed?
          delete_violations(merge_request)
        elsif merge_request.opened?
          schedule_timeout(merge_request)
        end
      end

      # Mirrors CleanupMergeRequestViolationsWorker, which ran before these rows were written.
      def delete_violations(merge_request)
        deleted = merge_request.scan_result_policy_violations.delete_all(:delete_all)
        @counts[:deleted_violations] += deleted
        @counts[:merged_or_closed_merge_requests] += 1

        log_policy_evaluation('sweep_stale_running_violations',
          'Deleted stale violations of a merged or closed merge request',
          Labkit::Fields::GL_PROJECT_ID => merge_request.target_project_id, merge_request_id: merge_request.id,
          deleted_violations: deleted)
      end

      def schedule_timeout(merge_request)
        pipeline = merge_request.diff_head_pipeline
        return unless pipeline&.complete_or_manual?

        ::Security::ScanResultPolicies::UnblockPendingMergeRequestViolationsWorker
          .perform_async(pipeline.id, { 'merge_request_id' => merge_request.id })
        @counts[:timed_out_merge_requests] += 1

        log_policy_evaluation('sweep_stale_running_violations',
          'Scheduled policy evaluation timeout for stale running violations',
          Labkit::Fields::GL_PROJECT_ID => merge_request.target_project_id, merge_request_id: merge_request.id,
          Labkit::Fields::GL_PIPELINE_ID => pipeline.id)
      end

      def enabled_for_project?(project_id)
        strong_memoize_with(:enabled_for_project, project_id) do
          Feature.enabled?(:sweep_stale_running_policy_violations, ::Project.actor_from_id(project_id))
        end
      end

      def load_cursor
        cursor = Gitlab::Redis::SharedState.with { |redis| redis.get(CURSOR_KEY) }
        cursor ? Gitlab::Json::SafeParser.parse(cursor) : {}
      end

      def save_cursor(violation)
        cursor = { 'updated_at' => violation.updated_at.iso8601(6), 'id' => violation.id }
        Gitlab::Redis::SharedState.with { |redis| redis.set(CURSOR_KEY, Gitlab::Json.dump(cursor), ex: CURSOR_TTL.to_i) }
      end

      def reset_cursor
        Gitlab::Redis::SharedState.with { |redis| redis.del(CURSOR_KEY) }
      end
    end
  end
end
