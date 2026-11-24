# frozen_string_literal: true

# Seeds the database tooling tables, which had neither a factory nor a fixture, so migrations
# touching them were never exercised by db:migrate:multi-version-upgrade.
#
# Several of these back a worker queue. The rows below are written in a state those workers
# have already finished with, so seeding them starts no cleanup, drop or reindex.
class Gitlab::Seeder::DatabaseArchitecture # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  # The table each deleted record points at is one the loose foreign key trigger really tracks
  # and routes to that sharded table, so the row matches what the trigger writes.
  DELETED_RECORD_SOURCES = {
    LooseForeignKeys::NamespaceDeletedRecord => ['public.clusters', :namespace_id],
    LooseForeignKeys::OrganizationDeletedRecord => ['public.ai_conversation_threads', :organization_id],
    LooseForeignKeys::ProjectDeletedRecord => ['public.approval_policy_rules', :project_id],
    LooseForeignKeys::UserDeletedRecord => ['public.chat_names', :user_id]
  }.freeze

  # Stands for a row already gone from the tracked table, which is what these records record.
  DELETED_ROW_ID = 999_999

  attr_reader :batched_job, :indexes

  def initialize
    @batched_job = Gitlab::Database::BackgroundMigration::BatchedJob.order(:id).first
    @indexes = Gitlab::Database::PostgresIndex.order(:identifier).limit(2).to_a
  end

  def seed!
    warn_missing_parents
    seed_job_transition_logs
    seed_deleted_records
    seed_reindex_actions
    seed_reindex_queued_actions
  end

  private

  # Naming the absent parents keeps a run that skips a section from reading like a full run.
  def warn_missing_parents
    missing = []
    missing << 'batched background migration job' if batched_job.nil?
    missing << 'postgres index' if indexes.empty?
    missing.concat(sharding_values.select { |_, value| value.nil? }.keys.map(&:to_s))
    return if missing.empty?

    warn "\nSkipping database architecture seeds that need: #{missing.join(', ')}"
  end

  # The organization comes off the project rather than being looked up on its own, so every
  # value here belongs to the same records the rows point at.
  def sharding_values
    @sharding_values ||= {
      namespace_id: Group.order(:id).first&.id,
      organization_id: project&.organization_id,
      project_id: project&.id,
      user_id: User.order(:id).first&.id
    }
  end

  def project
    @project ||= Project.order(:id).first
  end

  # One ordinary transition and one carrying the exception a failed job records.
  def seed_job_transition_logs
    return unless batched_job
    return if transition_log_model.exists?(batched_background_migration_job_id: batched_job.id)

    statuses = transition_log_model.previous_statuses

    rows = [
      { batched_background_migration_job_id: batched_job.id,
        previous_status: statuses[:pending], next_status: statuses[:running],
        exception_class: nil, exception_message: nil, created_at: now, updated_at: now },
      { batched_background_migration_job_id: batched_job.id,
        previous_status: statuses[:running], next_status: statuses[:failed],
        exception_class: 'StandardError', exception_message: 'Seeded transition failure',
        created_at: now, updated_at: now }
    ]

    transition_log_model.insert_all(rows, unique_by: %i[id created_at])
    print '.'
  end

  # Written as already processed: the cleanup worker only loads pending records, so these never
  # cause a child row to be deleted.
  def seed_deleted_records
    DELETED_RECORD_SOURCES.each do |model, (table_name, sharding_key)|
      value = sharding_values[sharding_key]
      next unless value
      next if model.exists?(fully_qualified_table_name: table_name)

      # `primary_key_value` identifies the row that was deleted from the tracked table, so it is
      # deliberately not the sharding key and deliberately does not resolve to a live row.
      # `partition` is left to the column default: the sliding list strategy moves it on to the
      # next partition, and a hardcoded one stops resolving once it has.
      model.insert_all(
        [{ primary_key_value: DELETED_ROW_ID, sharding_key => value,
           fully_qualified_table_name: table_name, status: model.statuses[:processed],
           cleanup_attempts: 0, consume_after: now, created_at: now }],
        unique_by: %i[partition id])
      print '.'
    end
  end

  # `create_for` is the model's own builder, so the row carries the sizes it reads off the index.
  # One action is finished and the other left running, which is the only state with a null end.
  def seed_reindex_actions
    return if indexes.empty?
    return if Gitlab::Database::Reindexing::ReindexAction.exists?

    Gitlab::Database::Reindexing::ReindexAction.create_for(indexes.first).finish
    Gitlab::Database::Reindexing::ReindexAction.create_for(indexes.last) if indexes.size > 1
    print '.'
  end

  # Queued in a finished state so the reindexing queue never picks them up.
  def seed_reindex_queued_actions
    return if indexes.empty?
    return if Gitlab::Database::Reindexing::QueuedAction.exists?

    states = Gitlab::Database::Reindexing::QueuedAction.states

    rows = indexes.each_with_index.map do |index, position|
      { index_identifier: index.identifier,
        state: position == 0 ? states[:done] : states[:failed],
        created_at: now, updated_at: now }
    end

    Gitlab::Database::Reindexing::QueuedAction.insert_all(rows)
    print '.'
  end

  def transition_log_model
    Gitlab::Database::BackgroundMigration::BatchedJobTransitionLog
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating database architecture data"

  Gitlab::Seeder::DatabaseArchitecture.new.seed!
end
