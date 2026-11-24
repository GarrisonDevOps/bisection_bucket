# frozen_string_literal: true

class MarkLegacyMigrationsIndexReadOnly < Elastic::Migration
  include ::Search::Elastic::MigrationHelper

  retry_on_failure

  def migrate
    unless helper.index_exists?(index_name: old_index_name)
      log "Old migrations index #{old_index_name} does not exist, skipping"
      return
    end

    return if completed?

    log "Starting migration to mark #{old_index_name} as read-only"

    helper.update_settings(
      index_name: old_index_name,
      settings: {
        index: {
          blocks: {
            write: true
          }
        }
      }
    )

    log "Migration complete. Index #{old_index_name} is now read-only"
  end

  def completed?
    return true unless helper.index_exists?(index_name: old_index_name)

    settings = client.indices.get_settings(index: old_index_name)
    index_settings = settings.dig(old_index_name, 'settings', 'index', 'blocks', 'write')

    index_settings.to_s == 'true'
  end

  private

  def old_index_name
    @old_index_name ||= helper.legacy_migrations_index_name
  end
end

MarkLegacyMigrationsIndexReadOnly.prepend ::Search::Elastic::MigrationObsolete
