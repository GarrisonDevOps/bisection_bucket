# frozen_string_literal: true

class ReindexMergeRequestsForTitleCompletion < Elastic::Migration
  skip_if -> { !Gitlab::Saas.feature_available?(:advanced_search) }

  def migrate
    Search::Elastic::ReindexingTask.create!(targets: %w[MergeRequest], options: { skip_pending_migrations_check: true })
  end

  def completed?
    true
  end
end

ReindexMergeRequestsForTitleCompletion.prepend ::Search::Elastic::MigrationObsolete
