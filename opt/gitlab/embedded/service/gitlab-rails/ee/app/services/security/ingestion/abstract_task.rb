# frozen_string_literal: true

module Security
  module Ingestion
    # Base class for all security ingestion tasks.
    #
    # This class implements the Template Method pattern, providing the foundation
    # for the pipeline design pattern used in security finding ingestion. Each task
    # in the ingestion pipeline inherits from this class and implements the
    # `#execute` method to perform a specific operation on the batch of findings.
    #
    # == Pipeline Design Pattern
    #
    # Security ingestion uses a pipeline of tasks (see {IngestSliceBaseService})
    # where each task:
    # 1. Receives a batch of {FindingMap} objects containing report data
    # 2. Performs its specific operation (e.g., creating records, updating associations)
    # 3. May annotate the FindingMap with IDs or state for downstream tasks
    #
    # Tasks are executed sequentially within database transactions, grouped by
    # database (SEC_DB_TASKS for gitlab_sec, MAIN_DB_TASKS for gitlab_main).
    #
    # == Interface Contract
    #
    # Subclasses MUST implement:
    # - `#execute` - Performs the task's operation and returns finding_maps
    #
    # Subclasses MAY use:
    # - `pipeline` - The CI pipeline being processed
    # - `finding_maps` - Array of {FindingMap} objects representing findings to ingest
    #
    # == Example Subclass
    #
    #   class Tasks::IngestFindings < AbstractTask
    #     def execute
    #       # Bulk insert findings, update finding_maps with generated IDs
    #       finding_maps
    #     end
    #   end
    #
    # @see FindingMap for the data structure passed between tasks
    # @see IngestSliceBaseService for the orchestration layer
    # @see IngestReportSliceService for the standard security scanner task list
    # @see IngestCvsSliceService for the CVS (continuous vulnerability scanning) task list
    class AbstractTask
      include Gitlab::Utils::StrongMemoize

      def self.execute(...)
        new(...).execute
      end

      def initialize(pipeline, finding_maps)
        @pipeline = pipeline
        @finding_maps = finding_maps
      end

      def execute
        raise "Implement the `execute` template method!"
      end

      private

      attr_reader :pipeline, :finding_maps
    end
  end
end
