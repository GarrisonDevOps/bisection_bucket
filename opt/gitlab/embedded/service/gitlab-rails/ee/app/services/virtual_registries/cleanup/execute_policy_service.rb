# frozen_string_literal: true

module VirtualRegistries
  module Cleanup
    class ExecutePolicyService
      CACHE_ENTRIES_CLASSES = {
        maven: ::VirtualRegistries::Packages::Maven::Cache::Remote::Entry,
        container: ::VirtualRegistries::Container::Cache::Remote::Entry
      }.freeze
      BATCH_SIZE = 250

      delegate :group, to: :policy, private: true

      def initialize(policy)
        @policy = policy
        @counts = CACHE_ENTRIES_CLASSES.transform_values { { deleted_entries_count: 0, deleted_size: 0 } }
      end

      def execute
        return ServiceResponse.error(message: 'Cleanup policy is required') unless policy

        CACHE_ENTRIES_CLASSES.each do |key, klass|
          process_cache_entries(key, klass)
        end

        ServiceResponse.success(payload: counts)
      rescue StandardError => e
        ServiceResponse.error(message: "Failed to execute cleanup policy: #{e.message}")
      end

      private

      attr_reader :policy, :counts

      def process_cache_entries(key, klass)
        target_entries = klass
          .for_group(policy.group_id)
          .default
          .requiring_cleanup(policy.keep_n_days_after_download)

        target_entries.each_batch(of: BATCH_SIZE, column: :iid) do |batch|
          result = mark_batch_for_destruction(batch)
          log_audit_events(klass, result.map { |_size, relative_path, iid| [relative_path, iid] })

          counts[key][:deleted_entries_count] += result.size
          counts[key][:deleted_size] += result.sum(&:first)
        end
      end

      def mark_batch_for_destruction(batch)
        sql = build_update_sql(batch)
        batch.connection.select_rows(sql)
      end

      def build_update_sql(batch)
        update_manager = build_update_manager(batch)
        "#{batch.connection.to_sql(update_manager)} RETURNING size, relative_path, iid"
      end

      def build_update_manager(batch)
        table = batch.arel_table
        Arel::UpdateManager.new(table).tap do |manager|
          manager.set([
            [table[:status], batch.model.statuses[:pending_destruction]],
            [table[:updated_at], Time.current]
          ])
          manager.wheres = batch.arel.constraints
        end
      end

      def log_audit_events(model, destroyed_paths)
        return if destroyed_paths.empty?

        event_name = "#{model.model_name.param_key}_deleted"
        entries = destroyed_paths.map { |relative_path, iid| model.new(group:, relative_path:, iid:) }

        ::VirtualRegistries::CreateAuditEventsService.new(entries:, event_name:).execute
      end
    end
  end
end
