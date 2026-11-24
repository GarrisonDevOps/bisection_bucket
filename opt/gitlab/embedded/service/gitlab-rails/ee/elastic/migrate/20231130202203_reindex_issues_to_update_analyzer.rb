# frozen_string_literal: true

class ReindexIssuesToUpdateAnalyzer < Elastic::Migration
  def migrate
    Search::Elastic::ReindexingTask.create!(targets: %w[Issue], options: { skip_pending_migrations_check: true })
  end

  def completed?
    true
  end
end

ReindexIssuesToUpdateAnalyzer.prepend ::Search::Elastic::MigrationObsolete
