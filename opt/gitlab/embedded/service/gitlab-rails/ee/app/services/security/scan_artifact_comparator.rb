# frozen_string_literal: true

module Security
  class ScanArtifactComparator
    # Sources not listed here default to priority 0.
    # This ensures scan execution policy (SEP) scans are processed first.
    SOURCE_PRIORITY_MAP = {
      scan_execution_policy: 100,
      pipeline_execution_policy: 50
    }.freeze

    def self.compare(artifact_a, artifact_b)
      new(artifact_a, artifact_b).execute
    end

    def initialize(artifact_a, artifact_b)
      @artifact_a = artifact_a
      @artifact_b = artifact_b
    end

    def execute
      # First: compare by source priority (SEP first)
      source_comparison = compare_by_source_priority
      return source_comparison unless source_comparison == 0

      # Second: if same source, compare by scanner order
      compare_by_scanner
    end

    private

    attr_reader :artifact_a, :artifact_b

    def compare_by_source_priority
      a_priority = source_priority(artifact_a.job&.job_source)
      b_priority = source_priority(artifact_b.job&.job_source)

      b_priority <=> a_priority
    end

    def compare_by_scanner
      report_a = artifact_a.security_report
      report_b = artifact_b.security_report

      return 0 if report_a.nil? && report_b.nil?
      return 1 if report_a.nil?
      return -1 if report_b.nil?

      report_a.scanner_order_to(report_b)
    end

    def source_priority(build_source)
      return 0 if build_source&.source.nil?

      SOURCE_PRIORITY_MAP[build_source.source.to_sym] || 0
    end
  end
end
