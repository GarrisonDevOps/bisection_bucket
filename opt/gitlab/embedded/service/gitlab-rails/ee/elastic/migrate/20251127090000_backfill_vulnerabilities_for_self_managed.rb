# frozen_string_literal: true

class BackfillVulnerabilitiesForSelfManaged < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  # Run only on self-managed instances that have Elasticsearch indexing enabled
  # and the vulnerabilities index available. It must be skipped on GitLab.com and GitLab Dedicated.
  skip_if -> { saas_with_es? || dedicated_with_es? }

  batch_size 30_000
  batched!
  throttle_delay 30.seconds
  retry_on_failure

  DOCUMENT_TYPE = ::Vulnerabilities::Read

  # Vulnerabilities do not honour this setting.
  def respect_limited_indexing?
    false
  end

  def item_to_preload
    { project: :namespace }
  end
end

BackfillVulnerabilitiesForSelfManaged.prepend ::Search::Elastic::MigrationObsolete
