# frozen_string_literal: true

class RemoveWorkItemDocumentsFromIssuesBasedOnSchemaVersion < Elastic::Migration
  include ::Search::Elastic::MigrationDeleteBasedOnSchemaVersion

  DOCUMENT_TYPE = Issue
  batch_size 20_000
  batched!
  throttle_delay 1.minute
  retry_on_failure

  def es_document_type
    'work_item'
  end

  def schema_version
    24_08
  end
end

RemoveWorkItemDocumentsFromIssuesBasedOnSchemaVersion.prepend ::Search::Elastic::MigrationObsolete
