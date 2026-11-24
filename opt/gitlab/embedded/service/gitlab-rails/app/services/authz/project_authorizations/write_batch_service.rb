# frozen_string_literal: true

module Authz
  module ProjectAuthorizations
    # Writes project_authorizations for one user on some projects, or for some users on one project, in
    # chunks of at most BATCH_SIZE IDs.
    #
    # Every value written is calculated after the locks are taken, from data read in the same transaction. Any
    # two writers that could write the same pair conflict on a lock, so an older calculation can't overwrite a
    # newer one, and a change committed after the calculation queues its own refresh, which runs later.
    #
    # A user writer locks its user exclusively. A project writer locks its project exclusively and its users
    # shared, so project writers on different projects that share a user run in parallel, while a user writer
    # still conflicts with any project writer holding its user. Project locks are always taken before user
    # locks, and each kind in ID order, so writers and waits can't deadlock.
    class WriteBatchService
      # Larger chunks hold locks longer but need far fewer transactions, locks and calculations. At this size one
      # user's rows on 1,000 projects delete in ~35 ms warm, and a 63k-user project's chunks hold locks ~0.4 s warm.
      BATCH_SIZE = 1_000

      # Advisory locks are shared by the whole database, so ours are taken as (namespace, ID) to keep them apart
      # from other code's locks. The numbers are arbitrary, but nothing else in GitLab may use them.
      USER_LOCK_NAMESPACE = 1_635_017_066
      PROJECT_LOCK_NAMESPACE = 1_635_017_067
      # The two-key lock functions take int4 keys.
      MAX_LOCK_KEY = (2**31) - 1
      LOCK_TIMEOUT = '5s'
      LOCK_ATTEMPTS = 3

      Result = Data.define(:rows_added, :rows_deleted) do
        def +(other)
          self.class.new(rows_added + other.rows_added, rows_deleted + other.rows_deleted)
        end
      end

      # Whether the stored rows already hold the calculated level: exactly one row, at that level. Several
      # rows for one pair are legacy duplicates, which count as changed so they get rewritten as one.
      #
      # @param levels [Array<Integer>] the stored access levels for one pair
      # @param level [Integer, nil] the calculated level; nil or NO_ACCESS means none
      def self.unchanged?(levels, level)
        level = level.to_i
        levels == [level] || (levels.empty? && level == Gitlab::Access::NO_ACCESS)
      end

      # Waits until no writer holds the user's lock, without keeping it, so a comparison after it sees every
      # earlier write. Exclusive, because project writers hold their users' locks shared.
      #
      # @param user_id [Integer]
      def self.wait_for_user_writers(user_id)
        ensure_outside_transaction!

        wait(lock_sql(USER_LOCK_NAMESPACE, [user_id]))
      end

      # Waits until no writer holds the project's lock or any of the users' locks, without keeping them, so a
      # comparison after it sees every earlier write. The project lock is waited for alone, before any user lock
      # is held, and the users at most BATCH_SIZE per transaction to bound the lock table.
      #
      # @param project_id [Integer]
      # @param user_ids [Array<Integer>]
      def self.wait_for_project_writers(project_id, user_ids)
        ensure_outside_transaction!

        wait(lock_sql(PROJECT_LOCK_NAMESPACE, [project_id], shared: true))
        user_ids.uniq.each_slice(BATCH_SIZE) do |batch|
          wait(lock_sql(USER_LOCK_NAMESPACE, batch, shared: true))
        end
      end

      def self.wait(sql)
        ::ProjectAuthorization.transaction do
          ::ProjectAuthorization.connection.execute("SET LOCAL lock_timeout = '#{LOCK_TIMEOUT}'")
          ::ProjectAuthorization.connection.execute(sql)
        end
      end
      private_class_method :wait

      # In tests only, honors ExclusiveLease's skip, which specs set where the transaction exists only because of
      # the spec. Production sets it for every after-commit callback, which may open a transaction of its own.
      def self.ensure_outside_transaction!
        return if Rails.env.test? && Gitlab::ExclusiveLease.skip_transaction_check?

        raise 'call this outside a transaction' if ::ProjectAuthorization.inside_transaction?
      end

      # One statement, in ID order, so writers locking overlapping IDs can't deadlock.
      def self.lock_sql(namespace, ids, shared: false)
        keys = ids.map { |id| Integer(id) }.uniq.sort
        raise ArgumentError, "ID #{keys.last} is too large for an advisory lock key" if keys.last > MAX_LOCK_KEY

        function = shared ? 'pg_advisory_xact_lock_shared' : 'pg_advisory_xact_lock'

        <<~SQL.squish
          SELECT count(#{function}(#{Integer(namespace)}, id))
          FROM (SELECT id FROM unnest(ARRAY[#{keys.join(',')}]::int[]) AS id ORDER BY id) sorted
        SQL
      end

      # Pass exactly one of user_id and project_id.
      def initialize(user_id: nil, project_id: nil)
        raise ArgumentError, 'pass exactly one of user_id and project_id' unless user_id.nil? ^ project_id.nil?

        @user_id = user_id
        @project_id = project_id
      end

      # Must be called outside any transaction: inside one, the locks and SET LOCAL would last until the
      # caller's commit, and the notifications would be published before it.
      #
      # @param ids [Array<Integer>] project IDs for a user, or user IDs for a project
      # @yieldparam ids [Array<Integer>] one chunk of the IDs, to calculate inside its transaction
      # @yieldreturn [Hash{Integer => Integer}] the access level per ID; a missing ID or NO_ACCESS means none
      # @return [Result]
      def execute(ids, &calculate)
        raise ArgumentError, 'a block is required' unless calculate

        self.class.ensure_outside_transaction!

        ids.uniq.each_slice(BATCH_SIZE).sum(Result.new(0, 0)) do |chunk|
          execute_chunk(chunk, calculate)
        end
      end

      private

      attr_reader :user_id, :project_id

      def execute_chunk(ids, calculate)
        attempts = 0

        begin
          attempts += 1
          changes, result = write(ids, calculate)
        rescue ActiveRecord::LockWaitTimeout
          retry if attempts < LOCK_ATTEMPTS

          raise
        end

        publish(changes)
        result || Result.new(0, 0)
      end

      # The rows are committed, so a failed publish mustn't fail the write; the notification is lost either
      # way, as it is today.
      def publish(changes)
        changes&.publish_written!
      rescue StandardError => e
        Gitlab::ErrorTracking.track_exception(e, user_id: user_id, project_id: project_id)
      end

      def write(ids, calculate)
        ::ProjectAuthorization.transaction do
          connection.execute("SET LOCAL lock_timeout = '#{LOCK_TIMEOUT}'")
          take_locks(ids)

          ::ApplicationRecord.uncached do
            scope = user_id ? ::User.find_by_id(user_id) : ::Project.find_by_id(project_id)
            next unless scope

            apply(scope, ids, calculate.call(ids), stored_levels(ids))
          end
        end
      end

      def stored_levels(ids)
        if user_id
          ::ProjectAuthorization.stored_levels_for_user(user_id, ids)
        else
          ::ProjectAuthorization.stored_levels_for_project(project_id, ids)
        end
      end

      # Changed pairs are deleted and inserted rather than updated in place: Siphon replicates the table
      # keyed by (user_id, project_id, access_level), so an update to access_level could leave the old level
      # in ClickHouse.
      def apply(scope, ids, fresh, stored)
        delete = []
        insert = []
        notify_add = []
        notify_remove = []

        ids.each do |id|
          level = fresh[id].to_i
          levels = stored.fetch(id, [])
          next if self.class.unchanged?(levels, level)

          if level == Gitlab::Access::NO_ACCESS
            delete << id
            notify_remove << id
            next
          end

          delete << id if levels.any?
          insert << row(id, level)
          # Rewriting duplicates to the level they already granted changes nobody's access.
          notify_add << row(id, level) unless levels.max == level
        end

        return if delete.empty? && insert.empty?

        deleted = delete_rows(delete)
        added = insert_rows(insert)
        [notifications(scope, notify_add, notify_remove), Result.new(added, deleted)]
      end

      def delete_rows(ids)
        return 0 if ids.empty?

        if user_id
          ::ProjectAuthorization.delete_for_user(user_id, ids)
        else
          ::ProjectAuthorization.delete_for_project(project_id, ids)
        end
      end

      # Joins users and projects, so a user or project deleted meanwhile gets no rows.
      def insert_rows(rows)
        return 0 if rows.empty?

        values = rows.map do |row|
          "(#{Integer(row[:user_id])}, #{Integer(row[:project_id])}, #{Integer(row[:access_level])})"
        end

        connection.exec_update(<<~SQL.squish, 'ProjectAuthorization Insert')
          INSERT INTO project_authorizations (user_id, project_id, access_level, is_unique)
          SELECT v.user_id, v.project_id, v.access_level, true
          FROM (VALUES #{values.join(',')}) AS v (user_id, project_id, access_level)
          INNER JOIN users ON users.id = v.user_id
          INNER JOIN projects ON projects.id = v.project_id
          ON CONFLICT DO NOTHING
        SQL
      end

      def notifications(scope, added, removed_ids)
        ::ProjectAuthorizations::Changes.new do |changes|
          changes.add(added)

          if user_id
            changes.remove_projects_for_user(scope, removed_ids)
          else
            changes.remove_users_in_project(scope, removed_ids)
          end
        end
      end

      def row(id, level)
        if user_id
          { user_id: user_id, project_id: id, access_level: level }
        else
          { user_id: id, project_id: project_id, access_level: level }
        end
      end

      def take_locks(ids)
        if user_id
          connection.execute(self.class.lock_sql(USER_LOCK_NAMESPACE, [user_id]))
        else
          connection.execute(self.class.lock_sql(PROJECT_LOCK_NAMESPACE, [project_id]))
          connection.execute(self.class.lock_sql(USER_LOCK_NAMESPACE, ids, shared: true))
        end
      end

      def connection
        ::ProjectAuthorization.connection
      end
    end
  end
end
