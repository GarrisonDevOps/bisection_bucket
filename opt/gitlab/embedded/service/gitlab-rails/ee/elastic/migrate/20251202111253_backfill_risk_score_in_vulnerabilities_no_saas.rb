# frozen_string_literal: true

class BackfillRiskScoreInVulnerabilitiesNoSaas < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  skip_if -> { saas_with_es? || !backfill_vulnerability_finding_risk_scores_completed? }

  batch_size 30_000
  batched!
  throttle_delay 30.seconds
  retry_on_failure

  QUEUE_THRESHOLD = 30_000
  DOCUMENT_TYPE = ::Vulnerabilities::Read

  def self.backfill_vulnerability_finding_risk_scores_completed?
    migration = Gitlab::Database::SharedModel.using_connection(SecApplicationRecord.connection) do
      Gitlab::Database::BackgroundMigration::BatchedMigration
        .find_for_configuration(
          :gitlab_sec,
          'BackfillVulnerabilityFindingRiskScores',
          :vulnerability_occurrences,
          :id,
          []
        )
    end

    migration&.finished? || migration&.finalized?
  end

  # We do not honour this setting for Dedicated.
  def respect_limited_indexing?
    false
  end

  def item_to_preload
    { project: :namespace }
  end
end

BackfillRiskScoreInVulnerabilitiesNoSaas.prepend ::Search::Elastic::MigrationObsolete
