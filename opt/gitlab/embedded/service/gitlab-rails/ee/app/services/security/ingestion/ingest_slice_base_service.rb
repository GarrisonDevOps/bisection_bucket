# frozen_string_literal: true

module Security
  module Ingestion
    # Base orchestration service for security finding ingestion.
    #
    # This service coordinates the execution of ingestion tasks for a batch (slice)
    # of security findings. It implements the pipeline design pattern by executing
    # a series of {AbstractTask} subclasses in sequence, passing {FindingMap} objects
    # through each task.
    #
    # == Database Partitioning
    #
    # GitLab uses multiple databases (gitlab_main and gitlab_sec). Security data
    # primarily lives in gitlab_sec, but some operations require gitlab_main.
    # This service handles this by defining two task lists:
    #
    # - `SEC_DB_TASKS` - Tasks that operate on gitlab_sec tables (findings,
    #   vulnerabilities, identifiers, etc.). Executed in a SecApplicationRecord
    #   transaction.
    #
    # - `MAIN_DB_TASKS` - Tasks that operate on gitlab_main tables (projects,
    #   namespaces, etc.). Executed in an ApplicationRecord transaction.
    #
    # == Subclass Contract
    #
    # Subclasses MUST define:
    # - `SEC_DB_TASKS` - Array of task class name symbols for gitlab_sec operations
    # - `MAIN_DB_TASKS` - Array of task class name symbols for gitlab_main operations
    #
    # == Execution Flow
    #
    # 1. Execute SEC_DB_TASKS within a gitlab_sec transaction
    # 2. Execute OWN_TRANSACTION_TASKS in a second gitlab_sec transaction
    # 3. Execute all MAIN_DB_TASKS within a gitlab_main transaction
    # 4. Update Elasticsearch indices for affected vulnerabilities
    # 5. Return the list of vulnerability IDs that were processed
    #
    # == Example Usage
    #
    #   class IngestReportSliceService < IngestSliceBaseService
    #     SEC_DB_TASKS = %i[IngestFindings IngestVulnerabilities ...].freeze
    #     MAIN_DB_TASKS = %i[].freeze
    #   end
    #
    #   IngestReportSliceService.execute(pipeline, finding_maps)
    #   # => [vulnerability_id_1, vulnerability_id_2, ...]
    #
    # @see AbstractTask for the task interface
    # @see FindingMap for the data structure passed between tasks
    # @see IngestReportSliceService for standard security scanner ingestion
    # @see IngestCvsSliceService for continuous vulnerability scanning ingestion
    class IngestSliceBaseService
      include Gitlab::Utils::StrongMemoize

      # `IngestVulnerabilityNamespaceStatistics` expands `traversal_ids`, so every project
      # under a group upserts that group's root row. Holding that lock for the rest of the
      # slice serialises unrelated projects, so it commits on its own instead.
      #
      # `SEC_DB_TASKS` must be symbols: this is matched against it by value, so a subclass
      # declaring strings yields an empty intersection and the split silently does nothing.
      OWN_TRANSACTION_TASKS = %i[IngestVulnerabilityNamespaceStatistics].freeze

      def self.execute(pipeline, finding_maps)
        new(pipeline, finding_maps).execute
      end

      def initialize(pipeline, finding_maps)
        @pipeline = pipeline
        @finding_maps = finding_maps
      end

      def execute
        run_tasks_in_sec_db
        run_own_transaction_tasks
        run_tasks_in_main_db

        update_elasticsearch

        vulnerability_ids
      end

      private

      attr_reader :pipeline, :finding_maps

      def run_tasks_in_sec_db
        ::SecApplicationRecord.transaction do
          project = pipeline&.project

          feature_enabled = Feature.enabled?(:turn_off_vulnerability_read_create_db_trigger_function,
            project || :instance)

          ::SecApplicationRecord.connection.execute("SELECT set_config(
          'vulnerability_management.dont_execute_db_trigger', '#{feature_enabled}', true);")

          sec_db_tasks.each { |task| execute_task(task) }
        end
      end

      def sec_db_tasks
        self.class::SEC_DB_TASKS - own_transaction_tasks
      end

      # Intersected with the subclass's own list, so a subclass that never declared the task
      # does not start running it, and no second transaction opens when there is nothing to run.
      def own_transaction_tasks
        self.class::SEC_DB_TASKS & OWN_TRANSACTION_TASKS
      end
      strong_memoize_attr :own_transaction_tasks

      # `run_tasks_in_sec_db` sets `dont_execute_db_trigger` with `is_local = true`, so it does
      # not carry into this transaction. Safe while the only task here avoids trigger tables;
      # anything added to `OWN_TRANSACTION_TASKS` that touches one needs the config set again.
      def run_own_transaction_tasks
        return if own_transaction_tasks.empty?

        ::SecApplicationRecord.transaction do
          own_transaction_tasks.each { |task| execute_task(task) }
        end
      end

      def run_tasks_in_main_db
        ::ApplicationRecord.transaction do
          self.class::MAIN_DB_TASKS.each { |task| execute_task(task) }
        end
      end

      def execute_task(task)
        Tasks.const_get(task, false).execute(pipeline, finding_maps)
      end

      def update_elasticsearch
        vulnerabilities = Vulnerability.id_in(vulnerability_ids)

        ::Vulnerabilities::BulkEsOperationService.new(vulnerabilities).execute
      end

      def vulnerability_ids
        @vulnerability_ids ||= finding_maps.map(&:vulnerability_id)
      end
    end
  end
end
