# frozen_string_literal: true

class BackfillDismissedVulnerabilities < Elastic::Migration
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

  def documents_after_current_id
    super.with_states(:dismissed)
  end
end
