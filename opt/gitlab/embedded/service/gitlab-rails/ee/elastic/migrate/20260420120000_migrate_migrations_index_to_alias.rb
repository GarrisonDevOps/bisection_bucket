# frozen_string_literal: true

class MigrateMigrationsIndexToAlias < Elastic::Migration
  include ::Search::Elastic::MigrationHelper

  retry_on_failure

  def migrate
    old_index_name = helper.legacy_migrations_index_name
    new_alias_name = helper.migrations_index_name

    # Early exit if migration already completed
    return if completed?

    log "Starting migration of migrations index from #{old_index_name} to #{new_alias_name}"

    # Create timestamped index without alias (alias added after verification)
    new_timestamped_index_name = helper.index_name_with_timestamp(new_alias_name)
    helper.create_index(
      index_name: new_timestamped_index_name,
      alias_name: new_alias_name,
      with_alias: false,
      settings: migrations_index_settings,
      mappings: migrations_index_mappings,
      options: { skip_if_exists: true }
    )

    log "Reindexing data from #{old_index_name} to #{new_timestamped_index_name}"
    reindex_result = client.reindex(
      body: {
        source: { index: old_index_name },
        dest: { index: new_timestamped_index_name }
      },
      wait_for_completion: true,
      refresh: true
    )

    log "Reindex completed", created: reindex_result['created'], updated: reindex_result['updated']

    old_count = client.count(index: old_index_name)['count']
    new_count = client.count(index: new_timestamped_index_name)['count']

    if old_count != new_count
      fail_migration_halt_error!(
        error: "Document count mismatch",
        old_count: old_count,
        new_count: new_count
      )
      return
    end

    log "Verified document counts match"

    helper.switch_alias(
      from: nil,
      to: new_timestamped_index_name,
      alias_name: new_alias_name
    )

    log "Created alias #{new_alias_name} for index #{new_timestamped_index_name}"
    log "Migration complete. Old index #{old_index_name} preserved for safety (can be manually deleted)"
  rescue StandardError => e
    fail_migration_halt_error!(error: e.message)
    raise
  end

  def completed?
    helper.alias_exists?(name: helper.migrations_index_name)
  end

  private

  def migrations_index_settings
    { number_of_shards: 1 }
  end

  def migrations_index_mappings
    {
      properties: {
        completed: { type: 'boolean' },
        state: { type: 'object' },
        started_at: { type: 'date' },
        completed_at: { type: 'date' },
        name: { type: 'keyword' }
      }
    }
  end
end

MigrateMigrationsIndexToAlias.prepend ::Search::Elastic::MigrationObsolete
