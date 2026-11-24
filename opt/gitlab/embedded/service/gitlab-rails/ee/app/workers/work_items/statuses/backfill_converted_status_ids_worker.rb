# frozen_string_literal: true

module WorkItems
  module Statuses
    class BackfillConvertedStatusIdsWorker
      include ApplicationWorker

      NAMESPACE_BATCH_SIZE = 100
      MAX_RUNTIME = 3.minutes
      RETRY_DELAY = 2.minutes

      data_consistency :sticky
      feature_category :team_planning
      urgency :low
      idempotent!
      deduplicate :until_executed, if_deduplicated: :reschedule_once
      concurrency_limit -> { 10 }
      defer_on_database_health_signal :gitlab_main_org, [:work_item_current_statuses], 1.minute
      sidekiq_options max_retries_after_interruption: 20

      def perform(root_namespace_id, cursor = nil)
        root_namespace = Group.find_by_id(root_namespace_id)
        return unless root_namespace&.custom_lifecycles&.exists?

        limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
        service = BackfillConvertedStatusIdsService.new(root_namespace)
        cursor = cursor&.symbolize_keys
        cursor = root_cursor(root_namespace) unless cursor && cursor_in_group?(cursor, root_namespace)
        resume_at = cursor.slice(:namespace_id, :iid) if cursor.values_at(:namespace_id, :iid).all?
        cursor = cursor.slice(:current_id, :depth)
        rewritten = 0
        inserted = 0
        resume_from = nil

        namespace_iterator(cursor).each_batch(of: NAMESPACE_BATCH_SIZE) do |namespace_ids, next_cursor|
          result = service.execute(namespace_ids, limiter, resume_at: resume_at).payload
          rewritten += result[:rewritten]
          inserted += result[:inserted]
          # The position only applies to the batch the previous job stopped in.
          resume_at = nil

          unless result[:completed]
            resume_from = cursor.merge(result[:resume_at])
            break
          end

          cursor = next_cursor
          next unless limiter.over_time?

          resume_from = cursor
          break
        end

        self.class.perform_in(RETRY_DELAY, root_namespace.id, resume_from.stringify_keys) if resume_from

        log_extra_metadata_on_done(:result, {
          rewritten: rewritten,
          inserted: inserted,
          over_time: limiter.was_over_time?,
          cursor: resume_from
        })
      end

      private

      def root_cursor(root_namespace)
        { current_id: root_namespace.id, depth: [root_namespace.id] }
      end

      # The iterator stops when the cursor's namespace no longer exists, and would walk another
      # group's tree if it moved. Either way, start over from the root.
      def cursor_in_group?(cursor, root_namespace)
        Namespace.by_root_id(root_namespace.id).id_in(cursor[:current_id]).exists?
      end

      def namespace_iterator(cursor)
        Gitlab::Database::NamespaceEachBatch.new(namespace_class: Namespace, cursor: cursor)
      end
    end
  end
end
