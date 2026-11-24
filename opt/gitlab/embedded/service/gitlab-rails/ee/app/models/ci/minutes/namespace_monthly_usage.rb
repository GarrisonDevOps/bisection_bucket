# frozen_string_literal: true

module Ci
  module Minutes
    # Track compute usage at root namespace level.
    # This class ensures that we keep MAX_NUMBER_OF_SHARDS record per namespace per month.
    # The number could eventually be modified, so the code supports variable shard numbers per month
    class NamespaceMonthlyUsage < Ci::ApplicationRecord
      include Ci::NamespacedModelName
      include AfterCommitQueue

      MAX_NUMBER_OF_SHARDS = 10
      FIRST_SHARD_NUMBER = 1

      belongs_to :namespace

      validates :shard_number,
        numericality: { greater_than_or_equal_to: FIRST_SHARD_NUMBER, less_than_or_equal_to: MAX_NUMBER_OF_SHARDS }
      validates :shard_number, uniqueness: { scope: [:namespace_id, :date] }

      scope :current_month, -> { where(date: beginning_of_month) }
      scope :for_namespace, ->(namespace) { where(namespace: namespace) }
      scope :for_shard, ->(shard_number) { where(shard_number: shard_number) }
      scope :by_namespace_and_date, ->(namespace, date) {
        where(namespace: namespace, date: date)
      }

      # Captures all shards of the last recorded month
      def self.all_previous_usages(namespace)
        date_subquery = for_namespace(namespace)
                          .where("#{quoted_table_name}.date < :date", date: beginning_of_month)
                          .select("MAX(#{quoted_table_name}.date)")

        by_namespace_and_date(namespace, date_subquery)
      end

      def self.beginning_of_month(time = Time.current)
        time.utc.beginning_of_month
      end

      def self.all_current_usages(namespace_id)
        current_month.for_namespace(namespace_id)
      end

      def self.total_current_minutes_used(namespace_id)
        all_current_usages(namespace_id).sum(:amount_used).to_i
      end

      def self.totals_for_namespaces(namespace_ids)
        current_month
          .where(namespace_id: namespace_ids)
          .group(:namespace_id)
          .sum(:amount_used)
      end

      # One record for each month, with the shard amounts added together. An Array is
      # returned on purpose: keyset pagination cannot page a grouped relation, while an
      # Array maps to ArrayConnection.
      def self.aggregated_by_month(namespace, date: nil)
        return [] unless namespace

        scope = for_namespace(namespace)
        scope = scope.where(date: date) if date

        scope
          .group(:date)
          .order(date: :desc)
          .select(:date, 'SUM(amount_used) AS amount_used',
            'SUM(shared_runners_duration) AS shared_runners_duration')
          .map do |row|
            new(
              namespace: namespace,
              date: row.date,
              amount_used: row.amount_used,
              shared_runners_duration: row.shared_runners_duration
            ).tap(&:readonly!)
          end
      end

      # We should always use this method to access data for the current month
      # since this will lazily create an entry if it doesn't exist.
      # For example, on the 1st of each month, when we update the usage for a namespace,
      # we will automatically generate new records and reset usage for the current month.
      # This also recalculates any additional compute minutes based on the previous month usage.
      #
      # Always resolves to the first shard, so the returned row does not depend on how many
      # shards the month holds.
      def self.find_or_create_current(namespace_id:)
        current_usage = unsafe_find_current_shard(namespace_id, FIRST_SHARD_NUMBER)
        return current_usage if current_usage

        if ::Gitlab::Database.read_only?
          return current_month.for_namespace(namespace_id).for_shard(FIRST_SHARD_NUMBER).new
        end

        find_or_create_first_shard(namespace_id)
      end

      # Sharded variant of `.find_or_create_current`. Instead of a single row per
      # namespace per month, writes are distributed across up to
      # MAX_NUMBER_OF_SHARDS rows to reduce write lock contention on
      # `ci_namespace_monthly_usages`. The shard is derived deterministically from
      # the `build_id` so retries for the same build always target the same row.
      #
      # Reads aggregate across shards (see `.all_current_usages`), so this is
      # behaviourally equivalent to `.find_or_create_current` when only one shard
      # exists.
      def self.find_or_create_current_shard(namespace_id:, build_id:)
        raise ArgumentError, 'build_id is required to select a shard' unless build_id

        shard_number = generate_shard_number(build_id)

        current_shard = unsafe_find_current_shard(namespace_id, shard_number)
        return current_shard if current_shard

        current_month_usages = current_month.for_namespace(namespace_id)
        return current_month_usages.for_shard(shard_number).new if ::Gitlab::Database.read_only?

        first_shard = find_or_create_first_shard(namespace_id)
        return first_shard if shard_number == FIRST_SHARD_NUMBER

        create_or_find_shard(namespace_id, shard_number)
      end

      # Concurrent builds resolve to different shards, so the unique index cannot elect
      # one quota recalculation between them. The first shard is the single row they all
      # compete for, so only the writer that creates it recalculates.
      def self.find_or_create_first_shard(namespace_id)
        first_shard = unsafe_find_current_shard(namespace_id, FIRST_SHARD_NUMBER)
        return first_shard if first_shard

        # A month that already holds shards was recalculated when it started.
        recalculate = !current_month.for_namespace(namespace_id).exists?

        create_or_find_shard(namespace_id, FIRST_SHARD_NUMBER) do |new_usage|
          new_usage.recalculate_quota_after_commit if recalculate
        end
      end
      private_class_method :find_or_create_first_shard

      # A concurrent creation is rejected by the uniqueness validation or, inside the
      # narrower window before the insert, by the unique index. The losing record never
      # commits, so the callback it queued never runs, and the loser reads the winning
      # row instead.
      def self.create_or_find_shard(namespace_id, shard_number)
        ::Gitlab::Database::QueryAnalyzers::PreventWritesOnGet.allow_write_on_get(
          url: 'https://gitlab.com/gitlab-org/gitlab/-/issues/608670') do
          current_month.for_namespace(namespace_id).for_shard(shard_number).new.tap do |new_usage|
            yield new_usage if block_given?

            new_usage.save!
          end
        end
      rescue ActiveRecord::RecordNotUnique, ActiveRecord::RecordInvalid
        unsafe_find_current_shard(namespace_id, shard_number) || raise
      end
      private_class_method :create_or_find_shard

      # Maps a build to one of the MAX_NUMBER_OF_SHARDS shards (1-indexed) using a
      # stable CRC32 hash so that a given build always resolves to the same shard.
      def self.generate_shard_number(build_id)
        (Zlib.crc32(build_id.to_s) % MAX_NUMBER_OF_SHARDS) + 1
      end

      # TODO: Remove in https://gitlab.com/gitlab-org/gitlab/-/issues/350617
      # Avoid cross-database modifications in transaction since
      # recalculation of purchased compute minutes touches `namespaces` table.
      def recalculate_quota_after_commit
        run_after_commit do
          Namespace.find_by_id(namespace_id).try do |namespace|
            Ci::Minutes::Quota.new(namespace).recalculate_remaining_purchased_minutes!
            Ci::Minutes::RefreshCachedDataWorker.perform_async(namespace_id)
          end
        end
      end

      def increase_usage(increments)
        increment_params = increments.select { |_attribute, value| value > 0 }
        return if increment_params.empty?

        # The use of `update_counters` ensures we do a SQL update rather than
        # incrementing the counter for the object in memory and then save it.
        # This is better for concurrent updates.
        self.class.update_counters(self, increment_params)
      end

      def self.reset_current_usage(namespace)
        update_current(namespace, amount_used: 0, notification_level: Notification::PERCENTAGES.fetch(:not_set))
      end

      def self.reset_current_notification_level(namespace)
        update_current(namespace, notification_level: Notification::PERCENTAGES.fetch(:not_set))
      end

      def self.update_current(namespace, attributes)
        current_month.for_namespace(namespace).update_all(attributes)
      end
      private_class_method :update_current

      # This is unsafe to use publicly because it would read the data
      # without creating a new record if doesn't exist.
      def self.unsafe_find_current_shard(namespace, shard_number)
        current_month.for_namespace(namespace).for_shard(shard_number).take
      end
      private_class_method :unsafe_find_current_shard

      # Notification_level is set to 100 (meaning 100% remaining compute minutes) by default.
      # It is reduced to 30 when the quota available drops below 30%
      # It is reduced to 5 when the quota available drops below 5%
      # It is reduced to 0 when the there are no more compute minutes available.
      #
      # Legacy tracking of compute usage (in `namespaces` table) uses 2 attributes instead.
      # We are condensing both into `notification_level` in the new monthly tracking.
      #
      # Until we retire the legacy compute usage tracking:
      #   * notification_level == 0 is equivalent to last_ci_minutes_notification_at being set
      #   * notification_level between 100 and 0 is equivalent to last_ci_minutes_usage_notification_level
      #     being set
      #   * notification_level == 100 is equivalent to neither of the legacy attributes being set,
      #     meaning that the quota used is still in the bucket 100%-to-30% used.
      #
      # Queries all shards rather than a single row so that a notification
      # recorded on one shard is visible even after writes are distributed
      # across shards (reference: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224699
      # and https://gitlab.com/gitlab-org/gitlab/-/work_items/490968 ).
      def self.any_usage_notified?(namespace_id, remaining_percentage)
        all_current_usages(namespace_id).where(notification_level: remaining_percentage).exists?
      end

      def self.any_total_usage_notified?(namespace_id)
        any_usage_notified?(namespace_id, Notification::PERCENTAGES.fetch(:exceeded))
      end
    end
  end
end
