# frozen_string_literal: true

class RemoveWorkItemFromIssuesIndex < Elastic::Migration
  include ::Search::Elastic::MigrationDeleteBasedOnSchemaVersion

  DOCUMENT_TYPE = Issue
  batch_size 10_000
  batched!
  throttle_delay 1.minute
  retry_on_failure

  def es_document_type
    'work_item'
  end

  def schema_version
    23_12
  end
end

RemoveWorkItemFromIssuesIndex.prepend ::Search::Elastic::MigrationObsolete
