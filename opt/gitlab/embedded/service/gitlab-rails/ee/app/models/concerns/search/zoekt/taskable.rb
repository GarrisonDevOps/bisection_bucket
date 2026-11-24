# frozen_string_literal: true

module Search
  module Zoekt
    module Taskable
      extend ActiveSupport::Concern

      PARTITION_DURATION = 1.day
      PARTITION_CLEANUP_THRESHOLD = 7.days
      PROCESSING_BATCH_SIZE = 100
      RETRY_DELAY = 5.minutes
      # Slack on top of the node-side indexing timeout, so a node that is slow
      # rather than dead keeps its claim.
      CLAIM_GRACE_PERIOD = 1.hour
      # Settings.indexing_timeout is nil while the setting is blank, and a claim
      # must still have an expiry then.
      FALLBACK_INDEXING_TIMEOUT = 30.minutes
      EXPIRED_CLAIM_BATCH_SIZE = 1_000

      included do
        include EachBatch
        include BulkInsertSafe
        include PartitionedTable

        self.primary_key = :id

        ignore_column :partition_id, remove_never: true
        attribute :retries_left, default: 3

        scope :for_partition, ->(partition) { where(partition_id: partition) }
        scope :join_nodes, -> { joins(:node) }
        scope :perform_now, -> { where(perform_at: (..Time.zone.now)) }
        scope :pending_or_processing, -> { where(state: %i[pending processing]) }
        scope :processing_queue, -> { perform_now.pending_or_processing }
        # A NULL claimed_until on a processing row predates the column, so it counts as expired.
        scope :with_expired_claim, -> do
          processing.where(claimed_until: ...Time.current).or(processing.where(claimed_until: nil))
        end

        enum :state, {
          pending: 0,
          processing: 1,
          done: 10,
          skipped: 250,
          failed: 255,
          orphaned: 256
        }

        partitioned_by :partition_id,
          strategy: :sliding_list,
          next_partition_if: ->(active_partition) { next_partition?(active_partition) },
          detach_partition_if: ->(partition) { detach_partition?(partition) }
      end

      class_methods do
        def next_partition?(active_partition)
          oldest_record_in_partition = self
            .select(:id, :created_at)
            .for_partition(active_partition.value)
            .order(:id)
            .first

          oldest_record_in_partition.present? && oldest_record_in_partition.created_at < PARTITION_DURATION.ago
        end

        def detach_partition?(partition)
          newest_task_older(partition, PARTITION_CLEANUP_THRESHOLD) && no_pending_or_processing(partition)
        end

        def newest_task_older(partition, duration)
          newest_record = self.select(:id, :created_at).for_partition(partition.value).order(:id).last
          return true if newest_record.nil?

          newest_record.created_at < duration.ago
        end

        def no_pending_or_processing(partition)
          !for_partition(partition.value).join_nodes.pending_or_processing.exists?
        end

        def each_task_for_processing(limit:)
          return unless block_given?

          process_tasks(limit) do |task|
            yield task
          end
        end

        def process_tasks(limit)
          count = 0
          processed_identifiers = Set.new

          task_iterator.each_batch(of: PROCESSING_BATCH_SIZE) do |tasks|
            task_states = tasks.each_with_object(valid: [], orphaned: [], skipped: [], done: []) do |task, states|
              case determine_task_state(task)
              when :done
                states[:done] << task.id
              when :orphaned
                states[:orphaned] << task.id
              when :skipped
                states[:skipped] << task.id
              when :valid
                next unless processed_identifiers.add?(task.per_batch_unique_id)

                states[:valid] << task.id

                yield task
                count += 1
              end

              break states if count >= limit
            end

            update_task_states(states: task_states)
            break if count >= limit
          end
        end

        def update_task_states(states:)
          id_in(states[:orphaned]).update_all(state: :orphaned, updated_at: Time.current) if states[:orphaned].any?
          id_in(states[:skipped]).update_all(state: :skipped, updated_at: Time.current) if states[:skipped].any?

          if states[:valid].any?
            # Already-`processing` rows are a re-presentation (the node poll
            # includes its own in-flight rows), not a new claim; excluding them
            # stops `claimed_until` renewing on every poll.
            id_in(states[:valid]).where.not(state: [:orphaned, :skipped, :done, :failed, :processing]).update_all(
              state: :processing, updated_at: Time.current, claimed_until: claim_expires_at
            )
          end

          return unless states[:done].any?

          done_tasks = id_in(states[:done])
          done_tasks.update_all(state: :done, updated_at: Time.current)
          on_tasks_done(done_tasks)
        end

        def claim_expires_at
          claim_offset.from_now
        end

        def claim_offset
          timeout = ::Search::Zoekt::Settings.indexing_timeout || FALLBACK_INDEXING_TIMEOUT

          timeout + CLAIM_GRACE_PERIOD
        end

        # A node that dies mid-task never reports back, so without this its claim
        # would hold the row in `processing` forever and block partition detachment.
        # Expiry is handled exactly like a reported failure: retry, then fail.
        def reset_expired_claims!
          # Unordered on purpose: every expired claim is reaped eventually, so the
          # batch does not need the lowest ids. Ordering forces the planner off
          # the `state` index onto a primary-key merge across all partitions,
          # which scans them in full when few rows are expired.
          ids = with_expired_claim.limit(EXPIRED_CLAIM_BATCH_SIZE).pluck_primary_key
          return { selected: 0, reaped: 0 } if ids.empty?

          # Re-assert `processing` in every write below: a node callback can land
          # between the select and the update, and its terminal state wins.
          retried_count = id_in(ids).processing.where(retries_left: 2..).update_all([
            'state = ?, retries_left = retries_left - 1, perform_at = ?, claimed_until = NULL, updated_at = NOW()',
            states[:pending], RETRY_DELAY.from_now
          ])

          failed_at = Time.current
          failed_count = id_in(ids).processing.where(retries_left: ...2).update_all(
            state: :failed, retries_left: 0, claimed_until: nil, updated_at: failed_at
          )

          if failed_count > 0
            # Matched on the tuple this update wrote, so the event fires only for
            # rows this run failed, not for rows a callback settled meanwhile.
            on_tasks_failed(id_in(ids).failed.where(retries_left: 0, updated_at: failed_at))
          end

          # `selected` answers "was this a full batch, is there more backlog",
          # `reaped` answers "how many rows did this run actually mutate". A
          # callback settling a row between the select and the writes makes them
          # differ, so the re-publish signal must not read the mutated count.
          { selected: ids.size, reaped: retried_count + failed_count }
        end

        def task_iterator
          raise NotImplementedError
        end

        def determine_task_state(task)
          raise NotImplementedError
        end

        def on_tasks_done(done_tasks)
          raise NotImplementedError
        end

        def on_tasks_failed(failed_tasks)
          raise NotImplementedError
        end

        def per_batch_unique_id
          raise NotImplementedError
        end
      end

      # `claimed_until` is the claim instant plus a fixed offset, so subtracting
      # the offset recovers it. The offset is read now but was baked in at claim
      # time, so prefer `plausible_claimed_at`.
      def claimed_at
        return unless claimed_until

        claimed_until - self.class.claim_offset
      end

      # A derived instant outside [perform_at, now] can only come from an offset
      # that changed under us. A change smaller than the task's own queue wait
      # or processing time passes, so this bounds the error, not detects it.
      def plausible_claimed_at(now = Time.current)
        derived = claimed_at
        return unless derived
        return if derived < perform_at || derived > now

        derived
      end
    end
  end
end
