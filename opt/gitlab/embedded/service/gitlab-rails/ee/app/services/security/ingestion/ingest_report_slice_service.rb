# frozen_string_literal: true

module Security
  module Ingestion
    # Base class to organize the chain of responsibilities
    # for the report slice.
    #
    # Returns the ingested vulnerability IDs.
    class IngestReportSliceService < IngestSliceBaseService
      # IncreaseCountersTask, IngestVulnerabilityStatistics and IngestVulnerabilityNamespaceStatistics
      # run last: each holds a row lock until its transaction commits, and the namespace one expands
      # traversal_ids so every project under a group contends on its root row. Running last shortens
      # that hold. The namespace one commits in its own transaction instead
      # (see IngestSliceBaseService::OWN_TRANSACTION_TASKS).
      SEC_DB_TASKS = %i[
        IngestIdentifiers
        IngestFindings
        IngestVulnerabilities
        AttachFindingsToVulnerabilities
        UpdateFindingEnrichmentVulnerabilities
        IngestFindingIdentifiers
        IngestFindingLinks
        IngestFindingSignatures
        IngestFindingEvidence
        IngestVulnerabilityFlags
        IngestVulnerabilityReads
        IngestRemediations
        IngestFindingRiskScores
        IncreaseCountersTask
        IngestVulnerabilityStatistics
        IngestVulnerabilityNamespaceStatistics
        HooksExecution
        MatchAscpComponents
      ].freeze

      # This needs to be defined for the IngestSliceBaseService to work.
      # If operations are added later that interact with gitlab_main tables,
      # they should be added here.
      MAIN_DB_TASKS = %i[].freeze

      def execute
        # This will halt execution of this slice but we will keep calling this service
        # for the rest of the finding maps.
        return [] unless ::Vulnerabilities::Quota.new(pipeline.project.reset).validate!

        Security::Ingestion::Tasks::UpdateVulnerabilityUuids.execute(@pipeline, @finding_maps)

        super
      end
    end
  end
end
