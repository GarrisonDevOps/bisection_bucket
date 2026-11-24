# frozen_string_literal: true

# Seeds the ActiveContext tables, which are empty in the upgrade stop dump, so migrations
# touching them were never exercised by db:migrate:multi-version-upgrade.
#
# `insert_all` is what lets one repository carry the null `enabled_namespace_id` the model
# rejects on create but the loose foreign key leaves behind in production.
class Gitlab::Seeder::GlobalSearchActiveContext # rubocop:disable Style/ClassAndModuleChildren -- seeder convention
  CONNECTION_NAME = 'Seeded ActiveContext connection'
  COLLECTION_CLASS = 'Ai::ActiveContext::Collections::Code'

  attr_reader :root_group, :project

  # The repository's project has to sit inside the enabled namespace, which is how the
  # application builds the pair. Picking each independently would produce a combination it
  # never creates. `find_each` keeps this to batches: under MASS_INSERT there can be a lot of
  # root groups and loading them all to scan would be the wrong shape on a seed path.
  def initialize
    @root_group = Group.where(parent_id: nil).find_each.find { |group| group.all_projects.exists? }
    @project = root_group.all_projects.order(:id).first if root_group
  end

  def seed!
    return warn_missing_dependencies unless root_group && project

    connection = seed_connection
    seed_collections(connection)
    seed_migrations(connection)
    seed_tasks(connection)
    enabled_namespace = seed_enabled_namespace(connection)
    seed_repositories(connection, enabled_namespace) if enabled_namespace
  end

  private

  def warn_missing_dependencies
    warn "\nSkipping ActiveContext seeds: no root group or project available"
  end

  # Built through the model, whose validations `insert_all` would bypass. Left inactive so the
  # application never resolves it and the deactivation worker, which drops indexed data, never runs.
  def seed_connection
    Ai::ActiveContext::Connection.find_by(name: CONNECTION_NAME) || create_connection
  end

  def create_connection
    connection = Ai::ActiveContext::Connection.create!(
      name: CONNECTION_NAME,
      adapter_class: 'ActiveContext::Databases::Postgresql::Adapter',
      options: { 'host' => 'localhost', 'port' => 5432, 'database' => 'seeded_active_context' },
      active: false
    )
    print '.'

    connection
  end

  # One collection carries every option the schema allows, the other leaves them at their
  # defaults. `chunk_strategy` and `chunk_strategy_size` are required together.
  def seed_collections(connection)
    return if Ai::ActiveContext::Collection.exists?(connection_id: connection.id)

    rows = [
      { connection_id: connection.id, name: 'seeded_collection', number_of_partitions: 2,
        metadata: { include_ref_fields: true, collection_class: COLLECTION_CLASS },
        options: { queue_shard_count: 2, queue_shard_limit: 100,
                   chunk_strategy: 'code_bytes', chunk_strategy_size: 512 },
        created_at: now, updated_at: now },
      { connection_id: connection.id, name: 'seeded_collection_defaults', number_of_partitions: 1,
        metadata: {}, options: {}, created_at: now, updated_at: now }
    ]

    Ai::ActiveContext::Collection.insert_all(rows, unique_by: %i[connection_id name])
    print '.'
  end

  # A failed row is the only shape allowed to carry no retries left, so the pair covers both
  # sides of that check constraint.
  def seed_migrations(connection)
    return if Ai::ActiveContext::Migration.exists?(connection_id: connection.id)

    statuses = Ai::ActiveContext::Migration.statuses
    rows = [
      { connection_id: connection.id, version: '20260101000000', status: statuses[:completed],
        retries_left: 3, started_at: now, completed_at: now, error_message: nil, metadata: {},
        created_at: now, updated_at: now },
      { connection_id: connection.id, version: '20260101000001', status: statuses[:failed],
        retries_left: 0, started_at: now, completed_at: nil, error_message: 'Seeded failure',
        metadata: {}, created_at: now, updated_at: now }
    ]

    Ai::ActiveContext::Migration.insert_all(rows, unique_by: %i[connection_id version])
    print '.'
  end

  # Only the primary key is unique here, so the guard is what keeps a re-run idempotent. The
  # second task depends on the first so the self reference is populated.
  def seed_tasks(connection)
    return if Ai::ActiveContext::Task.exists?(connection_id: connection.id)

    statuses = Ai::ActiveContext::Task.statuses
    completed = Ai::ActiveContext::Task.insert_all([
      { connection_id: connection.id, name: 'seeded_completed_task', status: statuses[:completed],
        retries_left: 3, depends_on_id: nil, started_at: now, completed_at: now,
        error_message: nil, params: { batch_size: 100 }, created_at: now, updated_at: now }
    ])

    Ai::ActiveContext::Task.insert_all([
      { connection_id: connection.id, name: 'seeded_pending_task', status: statuses[:pending],
        retries_left: 3, depends_on_id: completed.rows.dig(0, 0), started_at: nil,
        completed_at: nil, error_message: nil, params: {}, created_at: now, updated_at: now },
      { connection_id: connection.id, name: 'seeded_failed_task', status: statuses[:failed],
        retries_left: 0, depends_on_id: nil, started_at: now, completed_at: nil,
        error_message: 'Seeded task failure', params: {}, created_at: now, updated_at: now }
    ])
    print '.'
  end

  # The namespace must be a root group, and the metadata schema allows no properties at all.
  def seed_enabled_namespace(connection)
    existing = Ai::ActiveContext::Code::EnabledNamespace.find_by(
      connection_id: connection.id, namespace_id: root_group.id)
    return existing if existing

    # Partitioned, so the primary key `insert_all` would infer is composite and unusable here.
    Ai::ActiveContext::Code::EnabledNamespace.insert_all(
      [{ connection_id: connection.id, namespace_id: root_group.id,
         state: Ai::ActiveContext::Code::EnabledNamespace.states[:pending], metadata: {},
         created_at: now, updated_at: now }],
      unique_by: %i[connection_id namespace_id])
    print '.'

    Ai::ActiveContext::Code::EnabledNamespace.find_by(
      connection_id: connection.id, namespace_id: root_group.id)
  end

  # `last_commit` is set here rather than left to the model's `set_last_commit`, which reads the
  # value from Gitaly and would make a seed run depend on it.
  def seed_repositories(connection, enabled_namespace)
    return if Ai::ActiveContext::Code::Repository.exists?(connection_id: connection.id)

    Ai::ActiveContext::Code::Repository.insert_all(
      repository_rows(connection, enabled_namespace), unique_by: %i[connection_id project_id])
    print '.'
  end

  # The loose foreign key nullifies `enabled_namespace_id` when the namespace goes, so a second
  # row carries the shape the model rejects on create. Having no namespace to sit under, it is
  # the one row whose project does not have to come from the enabled hierarchy.
  def repository_rows(connection, enabled_namespace)
    states = Ai::ActiveContext::Code::Repository.states
    rows = [repository_row(connection, project, enabled_namespace.id, states[:pending])]
    orphaned = Project.where.not(id: project.id).order(:id).first
    return rows if orphaned.nil?

    rows << repository_row(connection, orphaned, nil, states[:pending_deletion])
  end

  def repository_row(connection, project, enabled_namespace_id, state)
    { connection_id: connection.id, project_id: project.id,
      enabled_namespace_id: enabled_namespace_id, state: state,
      last_commit: Gitlab::Git::SHA1_BLANK_SHA, metadata: {}, created_at: now, updated_at: now }
  end

  def now
    @now ||= Time.current
  end
end

Gitlab::Seeder.quiet do
  puts "\nGenerating ActiveContext data"

  Gitlab::Seeder::GlobalSearchActiveContext.new.seed!
end
