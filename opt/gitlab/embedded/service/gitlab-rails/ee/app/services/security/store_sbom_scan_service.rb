# frozen_string_literal: true

module Security
  class StoreSbomScanService < StoreScanService
    extend ::Gitlab::Utils::Override

    private

    override :store_findings
    def store_findings
      StoreSbomFindingsService.execute(security_scan, vulnerability_scanner, security_report, register_finding_keys,
        finding_uuids)

      security_scan.succeeded!
    rescue StandardError => error
      mark_scan_as_failed!

      Gitlab::ErrorTracking.track_exception(error)
    end

    def finding_uuids
      @finding_uuids ||= security_scan.findings.distinct_context_aware_uuids
    end
  end
end
