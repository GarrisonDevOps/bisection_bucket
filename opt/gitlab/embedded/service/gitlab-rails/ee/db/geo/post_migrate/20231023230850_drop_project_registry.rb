# frozen_string_literal: true

class DropProjectRegistry < Gitlab::Database::Migration[2.1]
  def up
    drop_table :project_registry
  end

  # rubocop:disable Layout/LineLength
  # rubocop:disable Metrics/AbcSize
  # rubocop:disable Migration/Datetime
  def down
    create_table :project_registry, id: :serial, force: :cascade do |t|
      t.integer :project_id, null: false
      t.datetime :last_repository_synced_at
      t.datetime :last_repository_successful_sync_at
      t.datetime :created_at, null: false
      t.boolean :resync_repository, default: true, null: false
      t.boolean :resync_wiki, default: true, null: false
      t.datetime :last_wiki_synced_at
      t.datetime :last_wiki_successful_sync_at
      t.integer :repository_retry_count
      t.datetime :repository_retry_at
      t.boolean :force_to_redownload_repository
      t.integer :wiki_retry_count
      t.datetime :wiki_retry_at
      t.boolean :force_to_redownload_wiki
      t.string :last_repository_sync_failure
      t.string :last_wiki_sync_failure
      t.string :last_repository_verification_failure
      t.string :last_wiki_verification_failure
      t.binary :repository_verification_checksum_sha
      t.binary :wiki_verification_checksum_sha
      t.boolean :repository_checksum_mismatch, default: false, null: false
      t.boolean :wiki_checksum_mismatch, default: false, null: false
      t.boolean :last_repository_check_failed
      t.datetime_with_timezone :last_repository_check_at
      t.datetime_with_timezone :resync_repository_was_scheduled_at
      t.datetime_with_timezone :resync_wiki_was_scheduled_at
      t.boolean :repository_missing_on_primary
      t.boolean :wiki_missing_on_primary
      t.integer :repository_verification_retry_count
      t.integer :wiki_verification_retry_count
      t.datetime_with_timezone :last_repository_verification_ran_at
      t.datetime_with_timezone :last_wiki_verification_ran_at
      t.binary :repository_verification_checksum_mismatched
      t.binary :wiki_verification_checksum_mismatched
      t.boolean :primary_repository_checksummed, default: false, null: false
      t.boolean :primary_wiki_checksummed, default: false, null: false

      t.index :project_id,
        name: :index_project_registry_on_project_id,
        unique: true,
        using: :btree

      t.index :repository_retry_at,
        name: :index_project_registry_on_repository_retry_at,
        using: :btree

      t.index :resync_repository,
        name: :index_project_registry_on_resync_repository,
        using: :btree

      t.index :resync_wiki,
        name: :index_project_registry_on_resync_wiki,
        using: :btree

      t.index :wiki_retry_at,
        name: :index_project_registry_on_wiki_retry_at,
        using: :btree

      t.index :last_repository_successful_sync_at,
        name: :index_project_registry_on_last_repository_successful_sync_at,
        using: :btree

      t.index :last_repository_synced_at,
        name: :index_project_registry_on_last_repository_synced_at,
        using: :btree

      t.index :repository_retry_count,
        name: :idx_project_registry_failed_repositories_partial,
        where: 'repository_retry_count > 0 OR last_repository_verification_failure IS NOT NULL OR repository_checksum_mismatch',
        using: :btree

      t.index :project_id,
        name: :idx_project_registry_on_repo_checksums_and_failure_partial,
        where: 'repository_verification_checksum_sha IS NULL AND last_repository_verification_failure IS NULL',
        using: :btree

      t.index :repository_verification_checksum_sha, name: :idx_project_registry_on_repository_checksum_sha_partial,
        where: 'repository_verification_checksum_sha IS NULL',
        using: :btree

      t.index :project_id,
        name: :idx_project_registry_on_repository_failure_partial,
        where: 'last_repository_verification_failure IS NOT NULL',
        using: :btree

      t.index :wiki_verification_checksum_sha, name: :idx_project_registry_on_wiki_checksum_sha_partial,
        where: 'wiki_verification_checksum_sha IS NULL',
        using: :btree

      t.index :project_id,
        name: :idx_project_registry_on_wiki_checksums_and_failure_partial,
        where: 'wiki_verification_checksum_sha IS NULL AND last_wiki_verification_failure IS NULL',
        using: :btree

      t.index :project_id,
        name: :idx_project_registry_on_wiki_failure_partial,
        where: 'last_wiki_verification_failure IS NOT NULL',
        using: :btree

      t.index :repository_retry_count,
        name: :idx_project_registry_pending_repositories_partial,
        where: "repository_retry_count IS NULL AND last_repository_successful_sync_at IS NOT NULL AND (resync_repository = 't' OR repository_verification_checksum_sha IS NULL AND last_repository_verification_failure IS NULL)",
        using: :btree

      t.index :last_repository_successful_sync_at,
        name: :idx_project_registry_synced_repositories_partial,
        where: "resync_repository = 'f' AND repository_retry_count IS NULL AND repository_verification_checksum_sha IS NOT NULL",
        using: :btree

      t.index :project_id,
        name: :idx_repository_checksum_mismatch,
        where: 'repository_checksum_mismatch = true',
        using: :btree

      t.index :project_id,
        name: :idx_wiki_checksum_mismatch,
        where: 'wiki_checksum_mismatch = true',
        using: :btree
    end
  end
  # rubocop:enable Layout/LineLength
  # rubocop:enable Metrics/AbcSize
  # rubocop:enable Migration/Datetime
end
