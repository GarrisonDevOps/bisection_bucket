# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    class RefreshEvent < ApplicationRecord
      include PartitionedTable

      PARTITION_DURATION = 1.day
      MAX_BACKOFF = 1.hour
      # How long a lease waits for a target's events queued just after the first one, so they share a run.
      DEBOUNCE = 10.seconds
      # Keeps every lease's statements bounded, for example a deleted user's event per membership. The rest
      # lease on the next round.
      MERGE_LIMIT = 1_000
      # Events that failed this often are reported, and don't hold up the verifier.
      POISON_ATTEMPTS = 5

      self.table_name = 'authz_refresh_events'
      self.primary_key = :id

      # Rails would cache the column default, so inserts would keep writing to the first partition.
      ignore_column :partition, remove_never: true

      scope :for_partition, ->(partition) { where(partition: partition) }

      enum :status, { pending: 1, processed: 2 }, prefix: :status

      partitioned_by :partition, strategy: :sliding_list,
        next_partition_if: ->(active_partition) do
          oldest = select(:id, :created_at).for_partition(active_partition.value).order(:id).limit(1).take
          oldest.present? && oldest.created_at < PARTITION_DURATION.ago
        end,
        detach_partition_if: ->(partition) { !for_partition(partition.value).status_pending.exists? }

      # Each type is named after what it recalculates, not what queued it, since several changes need the same work.
      enum :target_type, {
        # Every user's access to the project.
        project: 1,
        # The user's access to the project (scope), including what they lost if they're no longer a member.
        user_in_project: 2,
        # The user's access through the group (scope), including what they lost if they're no longer a member.
        user_in_group: 3,
        # All of the user's access.
        user: 4,
        # The projects under the namespace and, for a group, the projects shared with its subtree.
        namespace_subtree: 5,
        # The namespace's own projects that are shared with groups.
        namespace_project_group_links: 6,
        # The invited group's (target) direct members' access through the shared group (scope).
        group_group_link: 7
      }

      LeaseLostError = Class.new(StandardError)

      # Types that ExpandService turns into other events, rather than recalculating directly.
      EXPANSION_TYPES = %i[namespace_subtree namespace_project_group_links group_group_link].freeze
      # The types recalculated under each compute flag: project changes, and membership changes.
      COMPUTED_TYPES = { projects: %i[project user_in_project], memberships: %i[user_in_group user] }.freeze

      validates :target_type, :target_id, presence: true

      # The leased events for one target, by partition. `user_in_group` events merge by user, so `group_ids` lists
      # every leased group; for other types it holds scope_id. `first_queued_at` is the oldest among them.
      Lease = Data.define(:event_ids_by_partition, :target_type, :target_id, :group_ids, :cursor,
        :first_queued_at, :attempts) do
        def event_ids
          event_ids_by_partition.values.flatten
        end

        def scope_id
          group_ids.first
        end

        # The compute flag's actor: the project for the projects flag, the user for memberships.
        def actor_id
          target_type == :user_in_project ? scope_id : target_id
        end
      end

      class << self
        # Whether events of this type are recalculated, rather than dropped. Without an actor, whether they are
        # for every target. Memberships computes only once projects does for every target.
        #
        # @param target_type [Symbol] one of COMPUTED_TYPES
        # @param actor_id [Integer, nil] the project or user ID, as Lease#actor_id
        def computed?(target_type, actor_id = nil)
          # Recalculations only lock the rows they write, so every other writer must take the same locks first.
          return false unless Feature.enabled?(:authz_refresh_write_path) # rubocop:disable Gitlab/FeatureFlagWithoutActor -- must be on for every user
          return false unless Feature.enabled?(:authz_project_refresh_write_path) # rubocop:disable Gitlab/FeatureFlagWithoutActor -- must be on for every project

          if COMPUTED_TYPES[:projects].include?(target_type)
            Feature.enabled?(:authz_refresh_compute_projects, actor_id && ::Project.actor_from_id(actor_id))
          else
            Feature.enabled?(:authz_refresh_compute_projects) && # rubocop:disable Gitlab/FeatureFlagWithoutActor -- must be on for every project
              Feature.enabled?(:authz_refresh_compute_memberships, actor_id && ::User.actor_from_id(actor_id))
          end
        end

        # @param target_type [Symbol]
        # @return [Symbol, nil] the COMPUTED_TYPES group the type belongs to
        def group_of(target_type)
          COMPUTED_TYPES.find { |_group, types| types.include?(target_type) }&.first
        end

        # Whether the group's Sidekiq producers skip their refresh, leaving it to the queue: only while its Sidekiq
        # flag is off and it computes for every target, so the flag can't turn them off early.
        #
        # @param group [Symbol] a key of COMPUTED_TYPES
        def replaces_sidekiq?(group)
          computed?(COMPUTED_TYPES.fetch(group).first) && sidekiq_switched_off?(group)
        end

        # Whether the group's Sidekiq flag is off. Its producers only skip Sidekiq while it also computes for every
        # target, but its events that aren't computed go to the old workers whenever the flag is off, so turning
        # computing off before enabling the flag again never drops a change only the queue knows about.
        #
        # @param group [Symbol] a key of COMPUTED_TYPES
        def sidekiq_switched_off?(group)
          case group
          when :projects then Feature.disabled?(:authz_refresh_sidekiq_projects, :instance, type: :ops)
          when :memberships then Feature.disabled?(:authz_refresh_sidekiq_memberships, :instance, type: :ops)
          else raise ArgumentError, "unknown refresh group #{group}"
          end
        end

        # Leases the oldest ready event and every event it can share a run with: same target, attempts and cursor.
        # Equal attempts keep a failing event from dragging fresh ones into its backoff; equal cursors keep a
        # resumed run from skipping a newly merged group's projects below its cursor.
        #
        # @param duration [ActiveSupport::Duration] how long the events stay hidden from other workers
        # @param debounce [ActiveSupport::Duration]
        # @return [Lease, nil]
        def lease(duration:, debounce: DEBOUNCE)
          # The transaction keeps the statement on the primary, since the load balancer treats it as a read.
          # Uncached: the query cache would return an earlier lease's rows for the same SQL text.
          events = uncached do
            transaction do
              find_by_sql([LEASE_SQL, { duration: duration.to_i, debounce: debounce.to_i,
                                        user_in_group: target_types[:user_in_group], merge_limit: MERGE_LIMIT }])
            end
          end
          return if events.empty?

          first = events.min_by(&:id)
          Lease.new(
            event_ids_by_partition: events.group_by(&:event_partition).transform_values { |e| e.map(&:id).sort },
            target_type: first.target_type.to_sym,
            target_id: first.target_id,
            group_ids: events.map(&:scope_id).uniq.sort_by(&:to_i),
            cursor: first.cursor,
            first_queued_at: events.map(&:first_queued_at).min,
            attempts: first.attempts
          )
        end

        # Raises LeaseLostError, so the caller's transaction rolls back, when another worker leased the events
        # after this lease expired and finished them first.
        #
        # @param lease [Lease]
        def finish(lease)
          transaction do
            finished = leased_events_by_partition(lease).sum do |events|
              events.update_all(status: statuses[:processed])
            end
            raise LeaseLostError if finished < lease.event_ids.size
          end
        end

        # Makes the events visible again straight away, for a worker that is stopping.
        def release(lease)
          leased_events_by_partition(lease).each { |events| events.update_all('visible_at = now()') }
        end

        # Retries the events after a backoff that grows with each attempt. They're replaced with one more attempt
        # in the active partition, so a failing event never keeps an old partition alive.
        def fail(lease)
          backoff = [(2**lease.attempts).minutes, MAX_BACKOFF].min

          replace(lease, attempts: lease.attempts + 1, visible_at: backoff.from_now)
        end

        # Moves the leased events' cursor past work that's committed, so whoever leases them next resumes there.
        # Moving it only from the lease's own cursor stops two workers holding the same expired lease from both
        # doing the next batch: the second matches no rows and raises LeaseLostError.
        #
        # @return [Lease] the lease at the new cursor
        def advance(lease, cursor:)
          transaction do
            advanced = leased_events_by_partition(lease).sum do |events|
              events.where(cursor: lease.cursor).update_all(cursor: cursor)
            end
            raise LeaseLostError if advanced < lease.event_ids.size
          end

          lease.with(cursor: cursor)
        end

        # Replaces the leased events with one event per leased group, carrying the cursor the work got to, so
        # the next lease resumes there. They keep the events' age and attempts, for age alerts and backoff.
        def continue(lease, cursor:)
          replace(lease, cursor: cursor, attempts: lease.attempts)
        end

        # Whether an event that can still change the user's access to the project is ready or leased: one for
        # the user, the project, or a namespace it sits under. Poison events don't count.
        #
        # @param namespace_ids [Array<Integer>] the project's namespace and its ancestors
        def pending_for?(user_id:, project_id:, namespace_ids:)
          for_user = where(target_type: target_types.values_at(:user_in_group, :user), target_id: user_id)
          for_pair = where(target_type: :user_in_project, target_id: user_id, scope_id: project_id)
          for_project = where(target_type: :project, target_id: project_id)
          for_namespaces = where(
            target_type: target_types.values_at(:namespace_subtree, :namespace_project_group_links),
            target_id: namespace_ids)
          # A link event's target is the invited group; the shared group, whose reach changes, is its scope.
          for_shares = where(target_type: :group_group_link, scope_id: namespace_ids)

          status_pending.where(attempts: ...POISON_ATTEMPTS)
            .and(for_user.or(for_pair).or(for_project).or(for_namespaces).or(for_shares)).exists?
        end

        # Whether a namespace or share change event is pending anywhere. They expand into events for projects
        # that nothing on a pair's own ancestor path would show.
        def expansion_pending?
          status_pending.where(attempts: ...POISON_ATTEMPTS, target_type: target_types.values_at(*EXPANSION_TYPES))
            .exists?
        end

        # @param target_type [Symbol]
        # @param targets [Array<Integer>, Array<Array(Integer, Integer)>] target_id, or target_id and scope_id
        # @param first_queued_at [Time, nil] the age to carry over from the event these came from
        def enqueue(target_type, targets, first_queued_at: nil)
          type = target_types.fetch(target_type)
          targets.each_slice(1_000) do |batch|
            insert_events(batch.map do |target_id, scope_id|
              { target_type: type, target_id: target_id, scope_id: scope_id, first_queued_at: first_queued_at }.compact
            end)
          end
        end

        private

        # One transaction, so the leased events are never left half replaced. By default the new events keep the
        # leased events' own cursor, since an expansion advances it during the lease. Finishing first locks it.
        def replace(lease, attempts:, cursor: :leased, visible_at: nil)
          transaction do
            finish(lease)

            if cursor == :leased
              cursor = lease.event_ids_by_partition.filter_map do |partition, ids|
                for_partition(partition).where(id: ids).pick(:cursor)
              end.max
            end

            insert_events(lease.group_ids.map do |group_id|
              { target_type: target_types.fetch(lease.target_type), target_id: lease.target_id,
                scope_id: group_id, cursor: cursor, attempts: attempts, visible_at: visible_at,
                first_queued_at: lease.first_queued_at }
            end)
          end
        end

        # The lease returns each event's partition, so these statements go straight to it. In partition order, so
        # two workers holding the same expired lease lock its rows in the same order and can't deadlock.
        def leased_events_by_partition(lease)
          lease.event_ids_by_partition.sort.map do |partition, ids|
            status_pending.for_partition(partition).where(id: ids)
          end
        end

        # Without unique_by, insert_all looks for a unique index on id alone, but the primary key also holds the
        # partition. Ids come from a sequence, so nothing conflicts, and the partition's default picks the
        # active partition.
        def insert_events(rows)
          insert_all(rows, unique_by: %i[id partition])
        end
      end

      # The head is the oldest ready event no other lease holds; merged rows are locked with SKIP LOCKED too.
      # The gates are scalar subqueries, so one merge branch runs per statement and its scan follows
      # pending_on_target: user_in_group and unscoped events in scope_id order, or the head's own scope.
      LEASE_SQL = <<~SQL.squish
        WITH head AS (
          SELECT id, partition, target_type, target_id, scope_id, attempts, cursor FROM authz_refresh_events
          WHERE status = 1 AND (visible_at IS NULL OR visible_at <= now())
          ORDER BY id LIMIT 1
          FOR UPDATE SKIP LOCKED
        ), merged_any AS (
          SELECT events.id, events.partition FROM authz_refresh_events events, head
          WHERE events.status = 1
            AND events.target_type = (SELECT target_type FROM head)
            AND events.target_id = (SELECT target_id FROM head)
            AND events.attempts = head.attempts
            AND events.cursor IS NOT DISTINCT FROM head.cursor
            AND (events.visible_at IS NULL OR events.visible_at <= now() + make_interval(secs => :debounce))
            AND ((SELECT target_type FROM head) = :user_in_group OR (SELECT scope_id FROM head) IS NULL)
          ORDER BY events.scope_id LIMIT :merge_limit
          FOR UPDATE OF events SKIP LOCKED
        ), merged_scoped AS (
          SELECT events.id, events.partition FROM authz_refresh_events events, head
          WHERE events.status = 1
            AND events.target_type = (SELECT target_type FROM head)
            AND events.target_id = (SELECT target_id FROM head)
            AND events.scope_id = (SELECT scope_id FROM head)
            AND events.attempts = head.attempts
            AND events.cursor IS NOT DISTINCT FROM head.cursor
            AND (events.visible_at IS NULL OR events.visible_at <= now() + make_interval(secs => :debounce))
            AND (SELECT target_type FROM head) <> :user_in_group
          LIMIT :merge_limit
          FOR UPDATE OF events SKIP LOCKED
        )
        UPDATE authz_refresh_events events
        SET visible_at = now() + make_interval(secs => :duration)
        WHERE (events.id, events.partition) IN (
          SELECT id, partition FROM head
          UNION SELECT id, partition FROM merged_any
          UNION SELECT id, partition FROM merged_scoped
        )
        RETURNING events.id, events.partition AS event_partition, events.target_type, events.target_id,
          events.scope_id, events.attempts, events.cursor, events.first_queued_at
      SQL
    end
  end
end
