# frozen_string_literal: true

module Security
  module Ingestion
    class FindingMapCollection
      include Gitlab::Utils::StrongMemoize
      include Enumerable

      def initialize(pipeline, security_scan)
        @pipeline = pipeline
        @security_scan = security_scan
      end

      def each
        return to_enum(:each) unless block_given?

        deduplicated_findings.each do |security_finding|
          yield create_finding_map_for(security_finding)
        end
      end

      private

      attr_reader :pipeline, :security_scan

      delegate :findings, :report_findings, to: :security_scan, private: true

      def create_finding_map_for(security_finding)
        # For SAST findings, we override the finding UUID with an existing finding UUID
        # if we have a matching one.
        report_uuid = security_finding.overridden_uuid || security_finding.uuid

        FindingMap.new(
          pipeline,
          tracked_context(pipeline),
          security_finding,
          report_findings_map[report_uuid]
        )
      end

      def report_findings_map
        @report_findings_map ||= report_findings.index_by(&:uuid)
      end

      # Sorting will make sure the findings with `overridden_uuid` values will be
      # processed before the others.
      # We are also sorting by `uuid` to prevent having deadlock errors while
      # ingesting the findings.
      def deduplicated_findings
        findings.deduplicated.sort do |finding_a, finding_b|
          [finding_b.overridden_uuid.to_s, finding_b.uuid] <=> [finding_a.overridden_uuid.to_s, finding_a.uuid]
        end
      end
      strong_memoize_attr :deduplicated_findings

      def tracked_context_finder
        @tracked_context_finder ||= TrackedContextFinder.new
      end

      def tracked_context(pipeline)
        tracked_context_finder.find_or_create_from_pipeline(pipeline)
      end
    end
  end
end
