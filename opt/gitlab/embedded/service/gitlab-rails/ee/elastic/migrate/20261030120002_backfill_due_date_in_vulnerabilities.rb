# frozen_string_literal: true

class BackfillDueDateInVulnerabilities < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  batch_size 30_000
  batched!
  throttle_delay 30.seconds
  retry_on_failure

  DOCUMENT_TYPE = ::Vulnerabilities::Read

  def respect_limited_indexing?
    false
  end

  def item_to_preload
    { project: :namespace }
  end

  private

  # Page by finding ID so each batch reads only the next due dates, not all of them.
  def document_primary_key
    :vulnerability_occurrence_id
  end

  def documents_after_current_id
    super.with_due_date(after_finding_id: current_id)
  end
end
