# frozen_string_literal: true

module ClickHouse
  module DataIngestion
    class CiFinishedBuildsSyncService
      include Gitlab::ExclusiveLeaseHelpers
      include Gitlab::Utils::StrongMemoize

      # the job is scheduled every 3 minutes and we will allow maximum 6 minutes runtime
      # we must allow a minimum of 2 minutes + 15 seconds PG timeout + 1 minute for the various CH Gitlab::HTTP timeouts
      MAX_TTL = 6.minutes.to_i
      MAX_RUNTIME = 120.seconds
      BUILDS_BATCH_SIZE = 500
      BUILDS_BATCH_COUNT = 10 # How many batches to process before submitting the CSV to ClickHouse
      BUILD_ID_PARTITIONS = 100

      def self.enabled?
        ::Gitlab::ClickHouse.configured?
      end

      def initialize(worker_index: 0, total_workers: 1)
        @runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
        @worker_index = worker_index
        @total_workers = total_workers
      end

      def execute
        unless self.class.enabled?
          return ServiceResponse.error(
            message: 'Disabled: ClickHouse database is not configured.',
            reason: :db_not_configured,
            payload: service_payload
          )
        end

        # Prevent parallel jobs
        lock_key = ["#{self.class.name.underscore}/worker", @worker_index].join('/')
        in_lock(lock_key, ttl: MAX_TTL, retries: 0) do
          ::Gitlab::Database::LoadBalancing::SessionMap.without_sticky_writes do
            report = insert_new_finished_builds

            ServiceResponse.success(payload: report.merge(service_payload))
          end
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError => e
        # Skip retrying, just let the next worker to start after a few minutes
        ServiceResponse.error(message: e.message, reason: :skipped, payload: service_payload)
      end

      private

      def continue?
        !@reached_end_of_table && !@runtime_limiter.over_time?
      end

      def service_payload
        {
          worker_index: @worker_index,
          total_workers: @total_workers
        }
      end

      def insert_new_finished_builds
        # Read BUILDS_BATCH_COUNT batches of BUILDS_BATCH_SIZE until the timeout in MAX_RUNTIME is reached
        # We can expect a single worker to process around 2M builds/hour with a single worker,
        # and a bit over 5M builds/hour with three workers (measured in prod).
        @reached_end_of_table = false
        @processed_record_ids = []

        csv_batches.each do |csv_batch|
          break unless continue?

          csv_builder = CsvBuilder::Gzip.new(csv_batch, CSV_MAPPING)
          csv_builder.render do |tempfile|
            next if csv_builder.rows_written == 0

            File.open(tempfile.path) do |f|
              ClickHouse::Client.insert_csv(INSERT_FINISHED_BUILDS_QUERY, f, :main)
            end
          end
        end

        {
          records_inserted:
            Ci::FinishedBuildChSyncEvent.primary_key_in(@processed_record_ids).update_all(processed: true),
          reached_end_of_table: @reached_end_of_table
        }
      end

      def csv_batches
        events_batches_enumerator = Enumerator.new do |small_batches_yielder|
          # Main loop to page through the events
          keyset_iterator_scope.each_batch(of: BUILDS_BATCH_SIZE) { |batch| small_batches_yielder << batch }
          @reached_end_of_table = true
        end

        Enumerator.new do |batches_yielder|
          # Each batches_yielder value represents a CSV file upload
          while continue?
            batches_yielder << Enumerator.new do |records_yielder|
              # records_yielder sends rows to the CSV builder
              BUILDS_BATCH_COUNT.times do
                break unless continue?

                yield_builds(events_batches_enumerator.next, records_yielder)

              rescue StopIteration
                break
              end
            end
          end
        end
      end

      def yield_builds(events_batch, records_yielder)
        # NOTE: The `.to_a` call is necessary here to materialize the ActiveRecord relationship, so that the call
        # to `.last` in `.each_batch` (see https://gitlab.com/gitlab-org/gitlab/-/blob/a38c93c792cc0d2536018ed464862076acb8d3d7/lib/gitlab/pagination/keyset/iterator.rb#L27)
        # doesn't mess it up and cause duplicates (see https://gitlab.com/gitlab-org/gitlab/-/merge_requests/138066)
        build_ids = events_batch.to_a.pluck(:build_id) # rubocop: disable CodeReuse/ActiveRecord

        # rubocop: disable CodeReuse/ActiveRecord -- as it's tightly coupled with the select/joins specific to this sync
        Ci::Build.id_in(build_ids)
          .left_outer_joins(:runner_manager, :ci_stage, :job_definition_instance, runner: :owner_runner_namespace,
            project_mirror: :namespace_mirror)
          .preload(:job_artifacts_archive, runner: :tags)
          .select(*finished_build_projections)
          .each { |build| records_yielder << build }
        # rubocop: enable CodeReuse/ActiveRecord

        @processed_record_ids += build_ids
      end

      def finished_build_projections
        [
          *BUILD_FIELD_NAMES.map { |n| "#{::Ci::Build.table_name}.#{n}" },
          *BUILD_EPOCH_FIELD_NAMES.map { |n| "EXTRACT(epoch FROM #{::Ci::Build.table_name}.#{n}) AS casted_#{n}" },
          "#{::Ci::Build.table_name}.partition_id", # needed for partitioned preloads (job_artifacts_archive)
          "#{::Ci::NamespaceMirror.table_name}.traversal_ids[1] AS root_namespace_id",
          "#{::Ci::NamespaceMirror.table_name}.traversal_ids AS namespace_traversal_ids",
          "#{::Ci::Runner.table_name}.run_untagged AS runner_run_untagged",
          "#{::Ci::Runner.table_name}.runner_type AS runner_type",
          "#{::Ci::RunnerNamespace.table_name}.namespace_id AS runner_owner_namespace_id",
          *RUNNER_MANAGER_FIELD_NAMES.map { |n| "#{::Ci::RunnerManager.table_name}.#{n} AS runner_manager_#{n}" },
          *CI_STAGE_NAMES.map { |n| "#{::Ci::Stage.table_name}.#{n} AS ci_stage_#{n}" },
          "#{::Ci::JobDefinitionInstance.table_name}.job_definition_id AS job_definition_id",
          retries_count_sql
        ]
      end
      strong_memoize_attr :finished_build_projections

      def retries_count_sql
        <<~SQL.squish
          (SELECT COUNT(*)
           FROM #{::Ci::Build.table_name} AS retried_builds
           WHERE retried_builds.commit_id = #{::Ci::Build.table_name}.commit_id
             AND retried_builds.partition_id = #{::Ci::Build.table_name}.partition_id
             AND retried_builds.name = #{::Ci::Build.table_name}.name
             AND retried_builds.retried = TRUE) AS retries_count
        SQL
      end

      BUILD_FIELD_NAMES = %i[id project_id pipeline_id stage_id status name runner_id allow_failure user_id
        failure_reason when].freeze
      BUILD_EPOCH_FIELD_NAMES = %i[created_at queued_at started_at finished_at].freeze
      BUILD_COMPUTED_FIELD_NAMES = %i[root_namespace_id runner_owner_namespace_id group_name].freeze
      RUNNER_FIELD_NAMES = %i[run_untagged type].freeze
      RUNNER_MANAGER_FIELD_NAMES = %i[system_xid version revision platform architecture].freeze
      CI_STAGE_NAMES = %i[name].freeze

      CSV_MAPPING = {
        **BUILD_FIELD_NAMES.index_with { |n| n },
        **BUILD_EPOCH_FIELD_NAMES.index_with { |n| :"casted_#{n}" },
        **RUNNER_FIELD_NAMES.map { |n| :"runner_#{n}" }.index_with { |n| n },
        **BUILD_COMPUTED_FIELD_NAMES.index_with { |n| n },
        **RUNNER_MANAGER_FIELD_NAMES.map { |n| :"runner_manager_#{n}" }.index_with { |n| n },
        **CI_STAGE_NAMES.map { |n| :"stage_#{n}" }.index_with { |n| :"ci_#{n}" },
        namespace_path: ->(build) { "#{build.namespace_traversal_ids&.join('/')}/" },
        manual: ->(build) { build.action? },
        retries_count: ->(build) { build[:retries_count] },
        job_definition_id: ->(build) { build[:job_definition_id] },
        runner_tags: ->(build) { format_array_for_clickhouse(build.runner&.tag_list.to_a) },
        artifacts_filename: ->(build) { build.job_artifacts_archive&.file&.filename || "" },
        artifacts_size: ->(build) { build.job_artifacts_archive&.size || 0 }
      }.freeze

      def self.format_array_for_clickhouse(array)
        "[#{array.map { |s| "'#{s.to_s.gsub("'", "\\\\'")}'" }.join(',')}]"
      end

      INSERT_FINISHED_BUILDS_QUERY = <<~SQL.squish
        INSERT INTO ci_finished_builds (#{CSV_MAPPING.keys.join(',')})
        FORMAT CSV
      SQL

      def keyset_iterator_scope
        lower_bound = (@worker_index * BUILD_ID_PARTITIONS / @total_workers).to_i
        upper_bound = ((@worker_index + 1) * BUILD_ID_PARTITIONS / @total_workers).to_i - 1

        table_name = Ci::FinishedBuildChSyncEvent.quoted_table_name
        array_scope = Ci::FinishedBuildChSyncEvent.select(:build_id_partition)
          .from("generate_series(#{lower_bound}, #{upper_bound}) as #{table_name}(build_id_partition)") # rubocop: disable CodeReuse/ActiveRecord

        opts = {
          in_operator_optimization_options: {
            array_scope: array_scope,
            array_mapping_scope: ->(id_expression) do
              Ci::FinishedBuildChSyncEvent
                .where(Arel.sql("(build_id % #{BUILD_ID_PARTITIONS})") # rubocop: disable CodeReuse/ActiveRecord
                  .eq(id_expression))
            end
          }
        }

        scope = Ci::FinishedBuildChSyncEvent.pending.order_by_build_id

        Gitlab::Pagination::Keyset::Iterator.new(scope: scope, **opts)
      end
    end
  end
end
