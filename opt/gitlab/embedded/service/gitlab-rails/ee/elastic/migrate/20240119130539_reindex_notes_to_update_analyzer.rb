# frozen_string_literal: true

class ReindexNotesToUpdateAnalyzer < Elastic::Migration
  def migrate
    Search::Elastic::ReindexingTask.create!(targets: %w[Note], options: { skip_pending_migrations_check: true })
  end

  def completed?
    true
  end
end

ReindexNotesToUpdateAnalyzer.prepend ::Search::Elastic::MigrationObsolete
