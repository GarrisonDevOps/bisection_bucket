# frozen_string_literal: true

# This service stores the `Security::Scan` and
# `Security::Finding` records for the given job artifact.
#
# @param artifact [Ci::JobArtifact] the artifact to create scan and finding records from.
# @param known_keys [Set] the set of known finding keys stored by previous invocations of this service class.
# @param deduplicate [Boolean] attribute to force running deduplication logic.
# @param report [Gitlab::Ci::Reports::Security::Report, nil] the report to store.
#   When nil, defaults to artifact.security_report (the first/only report for the artifact).
#   Pass a specific report when storing individual reports from a multi-run artifact
#   (e.g. SARIF with multiple tool runs).
module Security
  class StoreScanService
    include Gitlab::Utils::StrongMemoize

    DEDUPLICATE_BATCH_SIZE = 50
    SCAN_INGESTION_ERROR = {
      type: 'ScanIngestionError',
      message: 'Ingestion failed for security scan'
    }.freeze

    def self.execute(artifact, known_keys, deduplicate, report: nil)
      new(artifact, known_keys, deduplicate, report: report).execute
    end

    def initialize(artifact, known_keys, deduplicate, report: nil)
      @artifact = artifact
      @known_keys = known_keys
      @deduplicate = deduplicate
      @security_report = report || artifact.security_report
    end

    def execute
      override_finding_uuids! if override_uuids?
      set_security_scan_non_latest! if job.retried?

      store_security_scan
      store_partial_scan

      return deduplicate if !security_scan.latest? || security_scan.report_error? || security_scan.job_failed?

      store_findings

      deduplicate_findings?
    end

    private

    attr_reader :artifact, :known_keys, :deduplicate, :security_report

    delegate :project, :job, to: :artifact, private: true
    delegate :pipeline, to: :job, private: true
    delegate :security_findings_partition_number, to: :pipeline, private: true

    def override_finding_uuids!
      OverrideUuidsService.execute(security_report)
    end

    def override_uuids?
      project.licensed_feature_available?(:vulnerability_finding_signatures)
    end

    def security_scan
      # rubocop:disable CodeReuse/ActiveRecord -- A class method would just be an alias of find_by
      # and would not offer any value in terms of code deduplication.
      #
      # scanner_external_id is nil for all single-scanner artifacts and is only set when a
      # single job produces multiple scans of the same type (e.g. a multi-run SARIF file
      # with one run per tool). The unique index uses NULLS NOT DISTINCT so two NULL values
      # are treated as equal, making nil the canonical sentinel for the single-scanner case.
      # Normalize empty string to nil so the uniqueness semantics are consistent.
      scan = Security::Scan.find_or_initialize_by(
        build: job,
        scan_type: security_report.type,
        scanner_external_id: security_report.scanner_external_id.presence
      )
      # rubocop:enable CodeReuse/ActiveRecord
      scan.created_at = pipeline.security_scans_created_at
      scan.processing_errors = security_report.errors.map(&:stringify_keys) if security_report.errored?
      scan.processing_warnings = security_report.warnings.map(&:stringify_keys) if security_report.warnings?
      scan.status = initial_scan_status
      scan.findings_partition_number = security_findings_partition_number
      scan.save!
      scan
    rescue ActiveRecord::RecordNotUnique
      # A record was created after `find_or_initialize_by` executed, but before the record was saved.
      # Try again, which should find the record.
      security_scan
    end
    strong_memoize_attr :security_scan
    alias_method :store_security_scan, :security_scan

    def store_partial_scan
      # If we have a dependency scanning report then `scan` will return nil
      mode = security_report.scan&.partial_scan_mode

      return unless mode

      Vulnerabilities::PartialScan.safe_find_or_create_by!(scan: security_scan) do |partial_scan|
        partial_scan.mode = mode
      end
    end

    def initial_scan_status
      return :report_error if security_report.errored?

      job.success? ? :preparing : :job_failed
    end

    def store_findings
      StoreFindingsService.execute(security_scan, vulnerability_scanner, security_report, register_finding_keys).then do |result|
        # If `StoreFindingsService` returns error, it means the findings
        # have already been stored before so we may re-run the deduplication logic.
        update_deduplicated_findings if result[:status] == :error && deduplicate_findings?
      end

      security_scan.succeeded!
    rescue StandardError => error
      mark_scan_as_failed!

      Gitlab::ErrorTracking.track_exception(error)
    end

    def set_security_scan_non_latest!
      security_scan.update!(latest: false)
    end

    def deduplicate_findings?
      deduplicate || security_scan.saved_changes?
    end

    def update_deduplicated_findings
      mark_all_findings_as_duplicate
      mark_unique_findings
    end

    def mark_all_findings_as_duplicate
      security_scan.findings.deduplicated.each_batch(of: DEDUPLICATE_BATCH_SIZE) { |batch| batch.update_all(deduplicated: false) }
    end

    def mark_unique_findings
      register_finding_keys.each_slice(DEDUPLICATE_BATCH_SIZE) do |batch|
        security_scan.findings
                     .by_uuid(batch)
                     .update_all(deduplicated: true)
      end
    end

    # This method registers all finding keys and
    # returns the UUIDs of the unique findings
    def register_finding_keys
      @register_finding_keys ||= security_report.findings.filter_map { |finding| register_keys(finding.keys) && finding.uuid }
    end

    def register_keys(keys)
      return if known_keys.intersect?(keys.to_set)

      known_keys.merge(keys)
    end

    def mark_scan_as_failed!
      security_scan.status = :preparation_failed

      security_scan.add_processing_error!(SCAN_INGESTION_ERROR)
    end

    def vulnerability_scanner
      project.vulnerability_scanners.safe_find_or_create_by!(external_id: security_report.scanner.external_id) do |scanner|
        scanner.assign_attributes(security_report.scanner.to_hash)
      end
    end
  end
end
