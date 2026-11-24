# frozen_string_literal: true

module Security
  module Ingestion
    # Orchestration service for Continuous Vulnerability Scanning (CVS) ingestion.
    #
    # CVS creates vulnerabilities from SBOM (Software Bill of Materials) data by
    # matching components against known advisories. Unlike traditional security
    # scanners that run during CI pipelines, CVS operates asynchronously when
    # advisory databases are updated or SBOM data changes.
    #
    # == Differences from IngestReportSliceService
    #
    # 1. **No pipeline context** - CVS findings are not tied to a specific CI
    #    pipeline run. The `pipeline` parameter is passed as `nil`.
    #
    # 2. **Specialized scanner task** - Uses `IngestCvsSecurityScanners` instead
    #    of the standard scanner ingestion, as CVS uses a dedicated virtual
    #    scanner (`gitlab-sbom-vulnerability-scanner`).
    #
    # 3. **MAIN_DB_TASKS** - Includes `MarkCvsProjectsAsVulnerable` to update
    #    project vulnerability status in gitlab_main.
    #
    # == Task List
    #
    # SEC_DB_TASKS (executed in gitlab_sec transaction):
    # - IngestCvsSecurityScanners - Creates/retrieves the CVS scanner record
    # - IngestIdentifiers - Creates vulnerability identifier records (CVE, CWE, etc.)
    # - IngestFindings - Creates vulnerability finding records
    # - IngestVulnerabilities - Creates/updates vulnerability records
    # - AttachFindingsToVulnerabilities - Links findings to vulnerabilities
    # - IngestFindingIdentifiers - Creates finding-identifier associations
    # - IngestFindingLinks - Creates external reference links
    # - IngestFindingSignatures - Creates finding signature records
    # - IngestFindingEvidence - Stores evidence data
    # - IngestVulnerabilityFlags - Sets vulnerability flags
    # - IngestVulnerabilityReads - Updates read-optimized vulnerability records
    # - IngestFindingRiskScores - Calculates and stores risk scores
    # - IncreaseCountersTask - Updates vulnerability counters
    # - IngestVulnerabilityStatistics - Updates project-level statistics
    # - IngestVulnerabilityNamespaceStatistics - Updates namespace-level statistics (in its own
    #   transaction, see IngestSliceBaseService::OWN_TRANSACTION_TASKS)
    # - HooksExecution - Triggers webhooks for new vulnerabilities
    #
    # MAIN_DB_TASKS (executed in gitlab_main transaction):
    # - MarkCvsProjectsAsVulnerable - Updates project.has_vulnerabilities flag
    #
    # @see IngestSliceBaseService for the base orchestration logic
    # @see Sbom::CreateVulnerabilitiesService for the CVS entry point
    # @see IngestReportSliceService for standard scanner ingestion
    class IngestCvsSliceService < IngestSliceBaseService
      # The three aggregate counter tasks run last on purpose. Each takes a row lock held
      # until its transaction commits, and they are the widest in the chain: one row per
      # project for the first two, and one per ancestor namespace for the third. The third
      # commits in its own transaction instead (see IngestSliceBaseService::OWN_TRANSACTION_TASKS).
      SEC_DB_TASKS = %i[
        IngestCvsSecurityScanners
        IngestIdentifiers
        IngestFindings
        IngestVulnerabilities
        AttachFindingsToVulnerabilities
        IngestFindingIdentifiers
        IngestFindingLinks
        IngestFindingSignatures
        IngestFindingEvidence
        IngestVulnerabilityFlags
        IngestVulnerabilityReads
        IngestFindingRiskScores
        IncreaseCountersTask
        IngestVulnerabilityStatistics
        IngestVulnerabilityNamespaceStatistics
        HooksExecution
      ].freeze

      MAIN_DB_TASKS = %i[
        MarkCvsProjectsAsVulnerable
      ].freeze

      def self.execute(finding_maps)
        super(nil, finding_maps)
      end
    end
  end
end
