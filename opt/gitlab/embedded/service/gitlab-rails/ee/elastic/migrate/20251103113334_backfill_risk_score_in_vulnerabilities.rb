# frozen_string_literal: true

class BackfillRiskScoreInVulnerabilities < Elastic::Migration
  include ::Search::Elastic::MigrationReindexBasedOnSchemaVersion

  skip_if -> { !saas_with_es? }

  batch_size 10_000
  batched!
  throttle_delay 15.seconds
  retry_on_failure

  DOCUMENT_TYPE = Vulnerability
  NEW_SCHEMA_VERSION = 25_45
end

BackfillRiskScoreInVulnerabilities.prepend ::Search::Elastic::MigrationObsolete
