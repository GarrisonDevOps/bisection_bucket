# frozen_string_literal: true

class ReindexMergeRequestToUpdateAnalyzer < Elastic::Migration
  def migrate
    Search::Elastic::ReindexingTask.create!(targets: %w[MergeRequest], options: { skip_pending_migrations_check: true })
  end

  def completed?
    true
  end
end

ReindexMergeRequestToUpdateAnalyzer.prepend ::Search::Elastic::MigrationObsolete
