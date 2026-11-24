# frozen_string_literal: true

class BackfillTokenStatusByReportTypesInVulnerabilities < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  skip_if -> { !(saas_with_es? || dedicated_with_es?) }

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
end

BackfillTokenStatusByReportTypesInVulnerabilities.prepend ::Search::Elastic::MigrationObsolete
