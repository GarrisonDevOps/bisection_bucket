# frozen_string_literal: true

class RemoveIssueDocumentsBasedOnSchemaVersion < Elastic::Migration
  include ::Search::Elastic::MigrationDeleteBasedOnSchemaVersion

  DOCUMENT_TYPE = Issue

  batch_size 10_000
  batched!
  throttle_delay 1.minute
  retry_on_failure

  def schema_version
    23_12
  end
end

RemoveIssueDocumentsBasedOnSchemaVersion.prepend ::Search::Elastic::MigrationObsolete
