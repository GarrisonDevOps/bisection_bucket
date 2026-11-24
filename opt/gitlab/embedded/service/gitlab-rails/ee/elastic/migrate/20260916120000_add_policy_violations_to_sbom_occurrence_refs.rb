# frozen_string_literal: true

class AddPolicyViolationsToSbomOccurrenceRefs < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Sbom::OccurrenceRef

  private

  def new_mappings
    {
      policy_violations: {
        type: 'short'
      }
    }
  end
end
