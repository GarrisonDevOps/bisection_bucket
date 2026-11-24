# frozen_string_literal: true

module Ci
  class RunnerManager < Ci::ApplicationRecord
    include FromUnion
    include RedisCacheable
    include Ci::HasRunnerExecutor
    include Ci::HasRunnerStatus

    # For legacy reasons, the table name is ci_runner_machines in the database
    self.table_name = 'ci_runner_machines'
    self.primary_key = :id

    query_constraints :id, :runner_type

    AVAILABLE_STATUSES = %w[online offline never_contacted stale].freeze
    AVAILABLE_STATUSES_INCL_DEPRECATED = AVAILABLE_STATUSES

    # The `UPDATE_CONTACT_COLUMN_EVERY` defines how often the Runner Machine DB entry can be updated
    UPDATE_CONTACT_COLUMN_EVERY = (40.minutes)..(55.minutes)

    # Limits how many distinct versions per runner can schedule a version update in each window
    RUNNER_VERSIONS_WINDOW = 1.hour
    MAX_RUNNER_VERSIONS_PER_WINDOW = 50

    EXECUTOR_NAME_TO_TYPES = {
      'unknown' => :unknown,
      'custom' => :custom,
      'shell' => :shell,
      'docker' => :docker,
      'docker-windows' => :docker_windows,
      'docker-ssh' => :docker_ssh,
      'ssh' => :ssh,
      'parallels' => :parallels,
      'virtualbox' => :virtualbox,
      'docker+machine' => :docker_machine,
      'docker-ssh+machine' => :docker_ssh_machine,
      'kubernetes' => :kubernetes,
      'docker-autoscaler' => :docker_autoscaler,
      'instance' => :instance
    }.freeze

    EXECUTOR_TYPE_TO_NAMES = EXECUTOR_NAME_TO_TYPES.invert.freeze

    belongs_to :runner, class_name: 'Ci::Runner', inverse_of: :runner_managers

    enum :creation_state, {
      started: 0,
      finished: 100
    }, suffix: true

    enum :runner_type, Runner.runner_types

    has_many :runner_manager_builds, inverse_of: :runner_manager, foreign_key: :runner_machine_id,
      class_name: 'Ci::RunnerManagerBuild'
    has_many :builds, through: :runner_manager_builds, class_name: 'Ci::Build'
    has_many :job_runtime_environments, inverse_of: :runner_manager, foreign_key: :runner_machine_id,
      class_name: 'Ci::JobRuntimeEnvironment'
    belongs_to :runner_version, inverse_of: :runner_managers, primary_key: :version, foreign_key: :version,
      class_name: 'Ci::RunnerVersion'

    validates :runner, presence: true
    validates :runner_type, presence: true, on: :create
    validates :system_xid, presence: true, length: { maximum: 64 }
    validates :organization_id, presence: true, on: [:create, :update], unless: :instance_type?
    validates :version, length: { maximum: 2048 }
    validates :revision, length: { maximum: 255 }
    validates :platform, length: { maximum: 255 }
    validates :architecture, length: { maximum: 255 }
    validates :ip_address, length: { maximum: 1024 }
    validates :config, json_schema: { filename: 'ci_runner_config' }
    validates :runtime_features, json_schema: { filename: 'ci_runner_runtime_features' }
    validates :labels, json_schema: { filename: 'ci_runner_labels' }

    validate :no_organization_id, if: :instance_type?

    cached_attr_reader :version, :revision, :platform, :architecture, :ip_address, :contacted_at,
      :executor_type, :creation_state

    # The `STALE_TIMEOUT` constant defines the how far past the last contact or creation date a runner manager
    # will be considered stale
    STALE_TIMEOUT = 7.days

    scope :stale, -> do
      stale_timestamp = stale_deadline

      from_union(
        never_contacted,
        where(contacted_at: ..stale_timestamp),
        remove_duplicates: false
      ).where(created_at: ..stale_timestamp)
    end

    # Managers created and last contacted before the deadline, or never contacted. Like `stale`, but with a
    # caller-chosen deadline, and without the union, because callers scope it to a single runner first.
    scope :not_contacted_since, ->(deadline) do
      where(created_at: ..deadline)
        .where(arel_table[:contacted_at].eq(nil).or(arel_table[:contacted_at].lteq(deadline)))
    end

    scope :for_runner, ->(runner) do
      scope = where(runner_id: runner)
      scope = scope.where(runner_type: runner.runner_type) if runner.is_a?(Ci::Runner) # Use unique index if possible

      scope
    end

    scope :with_system_xid, ->(system_xid) do
      where(system_xid: system_xid)
    end

    scope :order_id_desc, -> { order(id: :desc) }
    scope :order_contacted_at_desc, -> { order(arel_table[:contacted_at].desc.nulls_last) }

    scope :with_version_prefix, ->(value) do
      regex = version_regex_expression_for_version(value)
      value += '.' if regex.end_with?('\.') && !value.end_with?('.')
      substring = Arel::Nodes::NamedFunction.new('substring', [
        Ci::RunnerManager.arel_table[:version],
        Arel.sql("'#{regex}'::text")
      ])
      where(substring.eq(sanitize_sql_like(value)))
    end

    scope :with_upgrade_status, ->(upgrade_status) do
      joins(:runner_version).where(runner_version: { status: upgrade_status })
    end

    # [runner_id, runner_type] of the runners that created a manager since `time`.
    def self.runner_keys_created_since(time, limit:)
      where(created_at: time..).distinct.limit(limit).pluck(:runner_id, :runner_type)
    end

    def self.count_for_runner_key(runner_id, runner_type, limit:)
      where(runner_id: runner_id, runner_type: runner_type).limit(limit).count
    end

    # Deletes up to `limit` stale managers of one runner type, and returns [selected, deleted]. Each runner type is
    # a partition, and the `stale` scope without it fills its LIMIT from the first partition only. Fewer can be
    # deleted than selected, when a manager contacts GitLab or is deleted by someone else in between.
    def self.delete_stale(runner_type:, limit:)
      deadline = stale_deadline
      scope = where(runner_type: runner_type).not_contacted_since(deadline)
      # Each branch reads the contacted_at index in its order, so it reads only stale managers. Without the order, the
      # planner can scan the primary key instead, and each batch then filters out more live managers than the last.
      candidates = where(runner_type: runner_type).where(created_at: ..deadline)
        .order(contacted_at: :desc, id: :desc).limit(limit)
      ids = from_union(
        candidates.never_contacted,
        candidates.where(contacted_at: ..deadline),
        remove_duplicates: false,
        remove_order: false
      ).limit(limit).pluck(:id)
      return [0, 0] if ids.empty?

      [ids.size, scope.id_in(ids).delete_all]
    end

    # Deletes up to `limit` managers of the runner that haven't contacted GitLab since `deadline`, and returns how many
    # were deleted. Like Ci::Runners::StaleManagersCleanupService, it uses `delete_all`: loose foreign keys clean up the
    # child records. The conditions are repeated in the DELETE, so that a manager that contacts GitLab after being
    # selected is kept.
    def self.delete_not_contacted_since(runner, deadline, limit:)
      scope = for_runner(runner).not_contacted_since(deadline)
      ids = scope.limit(limit).pluck(:id)
      return 0 if ids.empty?

      scope.where(id: ids).delete_all
    end

    def self.online_contact_time_deadline
      Ci::Runner.online_contact_time_deadline
    end

    def self.stale_deadline
      STALE_TIMEOUT.ago
    end

    def self.aggregate_upgrade_status_by_runner_id
      joins(:runner_version)
        .group(:runner_id)
        .maximum(:status)
        .transform_values { |s| Ci::RunnerVersion.statuses.key(s).to_sym }
    end

    def self.version_regex_expression_for_version(version)
      case version
      when /\d+\.\d+\.\d+/
        '^\d+\.\d+\.\d+'
      when /\d+\.\d+(\.)?/
        '^\d+\.\d+\.'
      else
        '^\d+\.'
      end
    end

    def self.ids_with_running_builds(ids)
      return [] if ids.empty?

      id_in(ids).where_exists(
        ::Ci::RunningBuild
          .joins(:runner_manager_build)
          .where("#{::Ci::RunningBuild.quoted_table_name}.runner_id = #{quoted_table_name}.runner_id")
          .where("#{::Ci::RunnerManagerBuild.quoted_table_name}.runner_machine_id = #{quoted_table_name}.id")
      ).limit(ids.size).pluck(:id)
    end

    # Running builds leave out `canceling` builds because they're short-lived.
    def self.ids_with_running_builds_for_runner_managers(runner_managers)
      if Feature.enabled?(:ci_runner_manager_job_status_by_runner, Feature.current_request)
        ids_with_running_builds_by_runner(runner_managers)
      else
        ids_with_running_builds(runner_managers.map(&:id))
      end
    end

    # We read the running builds of the managers' runners once, so execution cost follows those builds,
    # and filter the managers outside the partitioned table, so planning doesn't repeat the filter per partition.
    def self.ids_with_running_builds_by_runner(runner_managers)
      return [] if runner_managers.empty?

      runner_manager_builds = ::Ci::RunnerManagerBuild.quoted_table_name
      running_builds = Gitlab::SQL::CTE.new(
        :running_builds,
        ::Ci::RunningBuild.where(runner_id: runner_managers.map(&:runner_id).uniq).select(:build_id, :partition_id)
      )
      running_managers = Gitlab::SQL::CTE.new(
        :running_managers,
        ::Ci::RunnerManagerBuild
          .joins(
            "INNER JOIN running_builds ON running_builds.build_id = #{runner_manager_builds}.build_id " \
              "AND running_builds.partition_id = #{runner_manager_builds}.partition_id"
          )
          .select(:runner_machine_id)
      )

      ::Ci::RunnerManagerBuild
        .with(running_builds.to_arel, running_managers.to_arel)
        .from(running_managers.alias_to(::Ci::RunnerManagerBuild.arel_table))
        .where(runner_machine_id: runner_managers.map(&:id))
        .distinct
        .limit(runner_managers.size)
        .pluck(:runner_machine_id)
    end
    private_class_method :ids_with_running_builds_by_runner

    def uncached_contacted_at
      read_attribute(:contacted_at)
    end

    def heartbeat(values)
      ##
      # We can safely ignore writes performed by a runner heartbeat. We do
      # not want to upgrade database connection proxy to use the primary
      # database after heartbeat write happens.
      #
      ::Gitlab::Database::LoadBalancing::SessionMap.current(load_balancer).without_sticky_writes do
        values = values&.slice(:version, :revision, :platform, :architecture, :ip_address, :config,
          :executor, :runtime_features, :labels) || {}

        values.merge!(contacted_at: Time.current, creation_state: :finished)

        if values.include?(:executor)
          values[:executor_type] = EXECUTOR_NAME_TO_TYPES.fetch(values.delete(:executor), :unknown)
        end

        new_version = values[:version]
        schedule_runner_version_update(new_version) if new_version && new_version != version

        merge_cache_attributes(values)

        # We save data without validation, it will always change due to `contacted_at`
        update_columns(values) if persist_cached_data?
      end
    end

    # While using update_columns may be useful from performance perspective, we still want
    # the `updated_at` column to be updated when actual runner attributes change.
    # However, we don't want to update it when only contacted_at changes, as this would
    # cause unnecessary incremental sync operations in downstream systems (e.g., Snowflake).
    def update_columns(attrs = {})
      # Only update columns that actually changed
      attrs_to_update = changed_values(attrs)

      attrs_to_update[:updated_at] = Time.current if attrs_to_update.except(:contacted_at, :creation_state).any?

      super(attrs_to_update) if attrs_to_update.any?
    end

    def supports_after_script_on_cancel?
      !!runtime_features['cancel_gracefully']
    end

    private

    def changed_values(values)
      # Always use read_attribute to get the actual database value, not cached value.
      values.select do |key, new_value|
        read_attribute(key) != new_value
      end
    end

    def persist_cached_data?
      # Use a random threshold to prevent beating DB updates.
      contacted_at_max_age = Random.rand(UPDATE_CONTACT_COLUMN_EVERY)

      real_contacted_at = uncached_contacted_at
      real_contacted_at.nil? ||
        (Time.current - real_contacted_at) >= contacted_at_max_age
    end

    def schedule_runner_version_update(new_version)
      return unless new_version && Gitlab::Ci::RunnerReleases.instance.enabled?
      return unless runner_version_update_allowed?(new_version)

      Ci::Runners::ProcessRunnerVersionUpdateWorker.perform_async(new_version)
    end

    def runner_version_update_allowed?(new_version)
      enforced = Feature.enabled?(:enforce_runner_version_update_limit, Ci::Runner.actor_from_id(runner_id))
      return true unless enforced || Feature.enabled?(:log_runner_version_update_limit, :instance)

      added, versions_count = track_runner_version(new_version)

      if added && versions_count > MAX_RUNNER_VERSIONS_PER_WINDOW
        Gitlab::AppJsonLogger.info(
          message: 'Runner version update limit exceeded',
          runner_id: runner_id,
          runner_manager_id: id,
          versions_count: versions_count,
          limit: MAX_RUNNER_VERSIONS_PER_WINDOW,
          enforced: enforced
        )

        return !enforced
      end

      added || !enforced
    rescue ::Redis::BaseError, ::RedisClient::Error => e
      # Failing open keeps the heartbeat working and enqueues as before the limit existed
      Gitlab::ErrorTracking.track_exception(e, runner_id: runner_id, runner_manager_id: id)
      true
    end

    # Fixed window: EXPIRE NX sets the TTL only when the first version is added
    def track_runner_version(new_version)
      key = "ci:runner:#{runner_id}:version_update_digests"

      added, _, versions_count = with_redis do |redis|
        redis.multi do |transaction|
          transaction.sadd?(key, Digest::SHA256.hexdigest(new_version))
          transaction.expire(key, RUNNER_VERSIONS_WINDOW.to_i, nx: true)
          transaction.scard(key)
        end
      end

      [added, versions_count]
    end

    def no_organization_id
      errors.add(:runner_manager, 'cannot have organization_id assigned') if organization_id
    end
  end
end
