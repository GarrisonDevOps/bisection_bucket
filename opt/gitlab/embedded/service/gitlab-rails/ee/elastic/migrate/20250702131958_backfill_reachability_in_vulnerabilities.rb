# frozen_string_literal: true

class BackfillReachabilityInVulnerabilities < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  skip_if -> { !(sass_with_es? || dedicated_with_es?) }

  batch_size 30_000
  batched!
  throttle_delay 30.seconds
  retry_on_failure

  QUEUE_THRESHOLD = 30_000
  DOCUMENT_TYPE = ::Vulnerabilities::Read

  # We do not honour this setting for SASS and Dedicated.
  # For Self-managed decision is pending and tracked in https://gitlab.com/gitlab-org/gitlab/-/issues/525484.
  def respect_limited_indexing?
    false
  end

  def item_to_preload
    { project: :namespace }
  end

  class << self
    def sass_with_es?
      Gitlab::CurrentSettings.elasticsearch_indexing? &&
        Gitlab::Saas.feature_available?(:advanced_search)
    end

    def dedicated_with_es?
      Gitlab::CurrentSettings.elasticsearch_indexing? &&
        Gitlab::CurrentSettings.gitlab_dedicated_instance?
    end
  end

  delegate :sass_with_es?, :dedicated_with_es?, to: :class
end

BackfillReachabilityInVulnerabilities.prepend ::Search::Elastic::MigrationObsolete
