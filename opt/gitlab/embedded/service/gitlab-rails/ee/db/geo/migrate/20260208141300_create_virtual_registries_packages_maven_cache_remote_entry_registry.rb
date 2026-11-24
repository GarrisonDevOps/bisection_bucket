# frozen_string_literal: true

class CreateVirtualRegistriesPackagesMavenCacheRemoteEntryRegistry < Gitlab::Database::Migration[2.3]
  milestone '18.10'

  def change
    create_table :virtual_registries_packages_maven_cache_remote_entry_registry, id: :bigserial, force: :cascade do |t|
      t.bigint :virtual_registries_packages_maven_cache_remote_entry_iid, null: false
      t.datetime_with_timezone :created_at, null: false
      t.datetime_with_timezone :last_synced_at
      t.datetime_with_timezone :retry_at
      t.datetime_with_timezone :verified_at
      t.datetime_with_timezone :verification_started_at
      t.datetime_with_timezone :verification_retry_at
      t.integer :state, default: 0, null: false, limit: 2
      t.integer :verification_state, default: 0, null: false, limit: 2
      t.integer :retry_count, default: 0, limit: 2, null: false
      t.integer :verification_retry_count, default: 0, limit: 2, null: false
      t.boolean :checksum_mismatch, default: false, null: false
      t.binary :verification_checksum
      t.binary :verification_checksum_mismatched
      t.text :verification_failure, limit: 255
      t.text :last_sync_failure, limit: 255

      t.index :virtual_registries_packages_maven_cache_remote_entry_iid,
        name: :idx_vreg_mvn_cache_remote_registry_on_entry_iid,
        unique: true
      t.index :retry_at, name: :idx_vreg_mvn_cache_remote_registry_on_retry_at
      t.index :state, name: :idx_vreg_mvn_cache_remote_registry_on_state
      # To optimize performance of VirtualRegistriesPackagesMavenCacheRemoteEntryRegistry.verification_failed_batch
      t.index :verification_retry_at,
        name: :idx_vreg_mvn_cache_remote_registry_failed_verification,
        order: "NULLS FIRST",
        where: "((state = 2) AND (verification_state = 3))"
      # To optimize performance of VirtualRegistriesPackagesMavenCacheRemoteEntryRegistry.needs_verification_count
      t.index :verification_state,
        name: :idx_vreg_mvn_cache_remote_registry_needs_verification,
        where: "((state = 2) AND (verification_state = ANY (ARRAY[0, 3])))"
      # To optimize performance of VirtualRegistriesPackagesMavenCacheRemoteEntryRegistry.verification_pending_batch
      t.index :verified_at,
        name: :idx_vreg_mvn_cache_remote_registry_pending_verification,
        order: "NULLS FIRST",
        where: "((state = 2) AND (verification_state = 0))"
    end
  end
end
