# frozen_string_literal: true

class RemoveIssueDocumentsBeforeSchemaVersion2408 < Elastic::Migration
  include ::Search::Elastic::MigrationDeleteBasedOnSchemaVersion

  DOCUMENT_TYPE = Issue

  batch_size 20_000
  batched!
  throttle_delay 1.minute
  retry_on_failure

  def schema_version
    24_08
  end
end

RemoveIssueDocumentsBeforeSchemaVersion2408.prepend ::Search::Elastic::MigrationObsolete
