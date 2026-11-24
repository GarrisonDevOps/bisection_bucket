# frozen_string_literal: true

module ClickHouse # rubocop:disable Gitlab/BoundedContexts -- matches the existing ClickHouse:: namespace used by every sibling
  module DataIngestion
    # Copies the root-namespace-to-organization mapping from Postgres into ClickHouse so the
    # traversal_path rebuild can resolve the org prefix without Siphon.
    # See https://gitlab.com/gitlab-org/gitlab/-/issues/608216
    class NamespaceOrganizationsSyncService
      include Gitlab::ExclusiveLeaseHelpers
      include Gitlab::Utils::StrongMemoize

      MAX_TTL = 10.minutes.to_i
      MAX_RUNTIME = 4.minutes
      BATCH_SIZE = 1_000
      BATCH_COUNT = 50 # batches per CSV upload

      CSV_MAPPING = {
        root_namespace_id: :id,
        organization_id: :organization_id
      }.freeze

      INSERT_QUERY = <<~SQL.squish
        INSERT INTO namespace_organizations (#{CSV_MAPPING.keys.join(',')})
        FORMAT CSV
      SQL

      def self.enabled?
        ::Gitlab::ClickHouse.configured?
      end

      def initialize
        @runtime_limiter = Gitlab::Metrics::RuntimeLimiter.new(MAX_RUNTIME)
      end

      def execute
        unless self.class.enabled?
          return ServiceResponse.error(message: 'Disabled: ClickHouse database is not configured.',
            reason: :db_not_configured)
        end

        in_lock(self.class.name.underscore, ttl: MAX_TTL, retries: 0) do
          ::Gitlab::Database::LoadBalancing::SessionMap.without_sticky_writes do
            ServiceResponse.success(payload: sync_namespaces)
          end
        end
      rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError => e
        ServiceResponse.error(message: e.message, reason: :skipped)
      end

      private

      attr_reader :runtime_limiter

      def continue?
        !@reached_end_of_table && !runtime_limiter.over_time?
      end

      def sync_namespaces
        @reached_end_of_table = false
        @records_written = 0

        csv_batches.each do |csv_batch|
          break unless continue?

          csv_builder = CsvBuilder::Gzip.new(csv_batch, CSV_MAPPING)
          csv_builder.render do |tempfile|
            next if csv_builder.rows_written == 0

            File.open(tempfile.path) { |f| ClickHouse::Client.insert_csv(INSERT_QUERY, f, :main) }
            @records_written += csv_builder.rows_written
          end
        end

        { records_written: @records_written, reached_end_of_table: @reached_end_of_table }
      end

      def csv_batches
        namespace_batches = Enumerator.new do |yielder|
          root_namespaces.each_batch(of: BATCH_SIZE) { |batch| yielder << batch }
          @reached_end_of_table = true
        end

        Enumerator.new do |batches_yielder|
          while continue?
            batches_yielder << Enumerator.new do |records_yielder|
              BATCH_COUNT.times do
                break unless continue?

                namespace_batches.next.each { |namespace| records_yielder << namespace }
              rescue StopIteration
                break
              end
            end
          end
        end
      end

      def root_namespaces
        # rubocop: disable CodeReuse/ActiveRecord -- narrow projection specific to this sync
        ::Namespace.where(parent_id: nil).select(:id, :organization_id)
        # rubocop: enable CodeReuse/ActiveRecord
      end
    end
  end
end
