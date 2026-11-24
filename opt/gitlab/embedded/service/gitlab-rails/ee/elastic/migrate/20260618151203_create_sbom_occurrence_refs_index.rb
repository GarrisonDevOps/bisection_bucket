# frozen_string_literal: true

class CreateSbomOccurrenceRefsIndex < Elastic::Migration
  include ::Search::Elastic::MigrationCreateIndexHelper

  retry_on_failure

  def document_type
    :sbom_occurrence_ref
  end

  def target_class
    ::Sbom::OccurrenceRef
  end
end
