# frozen_string_literal: true

module Sbom
  module Ingestion
    # Main orchestration service for SBOM (Software Bill of Materials) ingestion.
    #
    # This service processes CycloneDX SBOM reports from CI pipelines, creating
    # and updating component and occurrence records in the database. It serves
    # as the entry point for SBOM data ingestion and coordinates batch processing,
    # dependency graph building, and deduplication.
    #
    # == Input
    #
    # - `pipeline` - The CI pipeline that produced the SBOM report
    # - `sbom_report` - Parsed CycloneDX report containing components and sources
    #
    # == Processing Flow
    #
    # 1. **Build OccurrenceMapCollection** - Transforms report components into
    #    {OccurrenceMap} objects that track component/source/occurrence relationships
    #
    # 2. **Batch Processing** - Processes occurrences in slices of {BATCH_SIZE}
    #    (default: 10) via {IngestReportSliceService} to manage memory and
    #    transaction sizes
    #
    # 3. **Dependency Graph** - Optionally triggers async dependency graph building
    #    via {Sbom::BuildDependencyGraphWorker} when the report has changed
    #
    # == Deduplication
    #
    # The service uses a cache key based on report contents to prevent redundant
    # dependency graph builds. If the same report is processed multiple times
    # (e.g., pipeline retries), the graph build is skipped.
    #
    # == Output
    #
    # Returns an array of results from each slice's ingestion, which can be used
    # for tracking processed occurrence IDs.
    #
    # == Example
    #
    #   sbom_report = pipeline.sbom_reports.first
    #   Sbom::Ingestion::IngestReportService.execute(pipeline, sbom_report)
    #
    # @see OccurrenceMap for the data structure representing a single component
    # @see OccurrenceMapCollection for the collection wrapper
    # @see IngestReportSliceService for per-slice processing
    # @see DependencyGraphCacheKey for cache key generation
    class IngestReportService
      BATCH_SIZE = 10
      CACHE_EXPIRATION_TIME = 24.hours

      def self.execute(pipeline, sbom_report)
        new(pipeline, sbom_report).execute
      end

      def initialize(pipeline, sbom_report)
        @pipeline = pipeline
        @sbom_report = sbom_report
      end

      def execute
        results = occurrence_map_collection.each_slice(BATCH_SIZE).map do |slice|
          ingest_slice(slice)
        end
        build_dependency_graph
        results
      end

      private

      attr_reader :pipeline, :sbom_report

      delegate :project, to: :pipeline, private: true

      def occurrence_map_collection
        @occurrence_map_collection ||= OccurrenceMapCollection.new(pipeline, sbom_report)
      end

      def ingest_slice(slice)
        IngestReportSliceService.execute(pipeline, slice)
      end

      def build_dependency_graph
        return unless Feature.enabled?(:dependency_paths, project.group)

        if graph_needs_update?
          log_info("Building dependency graph")

          record_graph_updated

          ::Sbom::BuildDependencyGraphWorker.perform_async(project.id)
        else
          log_info("Graph already built")
        end
      end

      def graph_needs_update?
        # The cache key contains a hash of the report contents. If the cache key is present
        # in the store, we skip building the dependency graph since it has already been built
        # (or is currently being built by another process)
        Rails.cache.read(cache_key).nil?
      end

      def record_graph_updated
        # Write cache key before processing the graph so that we stop other graph builds
        # from starting in parallel before this one completes.
        Rails.cache.write(cache_key, { pipeline_id: pipeline.id }, expires_in: CACHE_EXPIRATION_TIME)
      end

      def log_info(message)
        ::Gitlab::AppLogger.info(
          message: message,
          project: project.name,
          project_id: project.id,
          namespace: project.namespace.name,
          namespace_id: project.namespace.id,
          cache_key: cache_key.to_s
        )
      end

      def cache_key
        @cache_key ||= Sbom::Ingestion::DependencyGraphCacheKey.new(project, sbom_report).key
      end
    end
  end
end
