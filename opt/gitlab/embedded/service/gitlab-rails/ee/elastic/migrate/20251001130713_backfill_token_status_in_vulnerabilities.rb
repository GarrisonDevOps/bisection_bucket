# frozen_string_literal: true

class BackfillTokenStatusInVulnerabilities < Elastic::Migration
  include ::Search::Elastic::MigrationReindexBasedOnSchemaVersion

  skip_if -> { !(saas_with_es? || dedicated_with_es?) }

  batch_size 10_000
  batched!
  throttle_delay 15.seconds
  retry_on_failure

  DOCUMENT_TYPE = Vulnerability
  NEW_SCHEMA_VERSION = 25_37

  class << self
    def saas_with_es?
      Gitlab::Saas.feature_available?(:advanced_search)
    end

    def dedicated_with_es?
      Gitlab::CurrentSettings.gitlab_dedicated_instance?
    end
  end

  delegate :saas_with_es?, :dedicated_with_es?, to: :class
end

BackfillTokenStatusInVulnerabilities.prepend ::Search::Elastic::MigrationObsolete
