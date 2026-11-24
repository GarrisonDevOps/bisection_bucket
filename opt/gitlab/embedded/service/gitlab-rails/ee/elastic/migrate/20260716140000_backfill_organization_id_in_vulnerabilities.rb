# frozen_string_literal: true

class BackfillOrganizationIdInVulnerabilities < Elastic::Migration
  include ::Search::Elastic::MigrationReindexBasedOnSchemaVersion

  batch_size 10_000
  batched!
  throttle_delay 15.seconds
  retry_on_failure

  DOCUMENT_TYPE = Vulnerability
  NEW_SCHEMA_VERSION = 26_06
end
