# frozen_string_literal: true

module Sbom
  # Re-indexes the occurrence refs a policy dismissal covers, so their indexed policy_violations
  # value reflects it.
  class TrackPolicyDismissalOccurrenceRefsService
    BATCH_SIZE = 100

    # @param policy_dismissal [Security::PolicyDismissal]
    def initialize(policy_dismissal)
      @policy_dismissal = policy_dismissal
    end

    # @return [void]
    def execute
      return if policy_dismissal.license_occurrence_uuids.blank?
      return unless ::Search::Elastic::SbomOccurrenceRefIndexHelper.indexing_allowed?

      policy_dismissal.license_occurrence_uuids.each_slice(BATCH_SIZE) do |uuids|
        ::Sbom::BulkEsOperationService.new(occurrence_refs(uuids)).execute
      end

      nil
    end

    private

    attr_reader :policy_dismissal

    def occurrence_refs(uuids)
      ::Sbom::OccurrenceRef.by_occurrence(::Sbom::Occurrence.by_uuids(uuids).select(:id))
    end
  end
end
