# frozen_string_literal: true

module Security
  class StoreGroupedScansService < ::BaseService
    include ::Gitlab::ExclusiveLeaseHelpers
    include ::Gitlab::Utils::StrongMemoize

    # Raised instead of waiting for the lease, so Sidekiq retries the job with a backoff
    # and the Sidekiq thread is not blocked. See Security::StoreScansWorker.
    LeaseTakenError = Class.new(::Gitlab::SidekiqMiddleware::RetryError)

    LEASE_TTL = 30.minutes
    LEASE_NAMESPACE = "store_grouped_scans"

    def self.execute(artifacts, pipeline, file_type, lease_owner: nil)
      new(artifacts, pipeline, file_type, lease_owner: lease_owner).execute
    end

    def initialize(artifacts, pipeline, file_type, lease_owner: nil)
      @artifacts = artifacts
      @pipeline = pipeline
      @known_keys = Set.new
      @file_type = file_type&.to_s
      @lease_owner = lease_owner
    end

    def execute
      scan_result = with_store_lease do |lease|
        sorted_artifacts.reduce(false) do |deduplicate, artifact|
          store_scan_for(artifact, deduplicate).tap { lease.renew if reentrant_lease? }
        end
      end

      record_error_rate
      scan_result
    rescue Gitlab::ExclusiveLeaseHelpers::FailedToObtainLockError
      raise LeaseTakenError, "Another job is storing the #{file_type} scans of pipeline #{pipeline.id}"
    rescue Gitlab::Ci::Parsers::ParserError => error
      Gitlab::ErrorTracking.track_exception(error)
    ensure
      artifacts.each(&:clear_security_report)
    end

    private

    attr_reader :artifacts, :pipeline, :known_keys, :file_type, :lease_owner

    def with_store_lease(&block)
      return with_reentrant_lease(&block) if reentrant_lease?

      in_lock(lease_key, ttl: LEASE_TTL, retries: 0) { |_retried, lease| yield lease }
    end

    # The Sidekiq job ID does not change between retries, so a lease with our job ID is renewed.
    # A requeued job can rarely run while its earlier run is still alive; both runs then store scans.
    def with_reentrant_lease
      lease = Gitlab::ExclusiveLease.new(lease_key, timeout: LEASE_TTL, uuid: lease_owner)

      raise FailedToObtainLockError, 'Failed to obtain a lock' unless lease.try_obtain || lease.renew

      yield lease
    ensure
      lease.cancel
    end

    def reentrant_lease?
      return false if lease_owner.blank?

      Feature.enabled?(:store_scans_reentrant_lease, pipeline.project)
    end
    strong_memoize_attr :reentrant_lease?

    def lease_key
      "#{LEASE_NAMESPACE}:#{pipeline.id}:#{file_type}"
    end

    def sorted_artifacts
      @sorted_artifacts ||= artifacts.each { |artifact| prepare_reports_for(artifact) }.sort do |a, b|
        ScanArtifactComparator.compare(a, b)
      end
    end

    def prepare_reports_for(artifact)
      artifact.security_reports(validate: true)
    end

    # For most artifact types security_reports returns a single-element array and
    # this reduces to the original one-scan-per-artifact behavior. For multi-run
    # SARIF artifacts it iterates each report and stores a separate Security::Scan
    # per run, keyed by scanner_external_id in the unique index.
    def store_scan_for(artifact, deduplicate)
      artifact.security_reports.reduce(deduplicate) do |dedup, report|
        StoreScanService.execute(artifact, known_keys, dedup, report: report)
      end
    end

    def record_error_rate
      return if Feature.disabled?(:security_scan_error_rate, Feature.current_request, type: :wip)

      sorted_artifacts.each do |artifact|
        artifact.security_reports.each do |report|
          scan = report.scan

          next unless scan

          feature_category = Enums::Vulnerability.report_type_feature_category(scan.type)

          Gitlab::Metrics::SecurityScanSlis.error_rate.increment(
            labels: { scan_type: scan.type, feature_category: feature_category },
            # https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/941f497a3824d4393eb8a7efced497f738895ab4/src/security-report-format.json#L128
            error: scan.status != "success"
          )
        end
      end
    end
  end
end
