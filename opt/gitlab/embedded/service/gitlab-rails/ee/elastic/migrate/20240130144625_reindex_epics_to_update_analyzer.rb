# frozen_string_literal: true

class ReindexEpicsToUpdateAnalyzer < Elastic::Migration
  def migrate
    Search::Elastic::ReindexingTask.create!(targets: %w[Epic], options: { skip_pending_migrations_check: true })
  end

  def completed?
    true
  end
end

ReindexEpicsToUpdateAnalyzer.prepend ::Search::Elastic::MigrationObsolete
