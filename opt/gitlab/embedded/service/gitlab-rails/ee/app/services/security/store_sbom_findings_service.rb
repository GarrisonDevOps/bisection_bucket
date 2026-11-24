# frozen_string_literal: true

module Security
  class StoreSbomFindingsService < StoreFindingsService
    extend ::Gitlab::Utils::Override
    include ::Gitlab::Utils::Executable

    attr_reader :existing_finding_uuids

    def initialize(security_scan, scanner, report, deduplicated_finding_uuids, existing_finding_uuids)
      super(security_scan, scanner, report, deduplicated_finding_uuids)

      @existing_finding_uuids = existing_finding_uuids
    end

    override :execute
    def execute
      store_findings
      success
    end

    private

    override :report_findings
    def report_findings
      report.findings.select do |finding|
        finding.valid? && existing_finding_uuids.exclude?(finding.uuid)
      end
    end
  end
end
