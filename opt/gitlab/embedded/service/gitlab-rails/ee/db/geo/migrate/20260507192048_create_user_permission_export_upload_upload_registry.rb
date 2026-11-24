# frozen_string_literal: true

class CreateUserPermissionExportUploadUploadRegistry < Gitlab::Database::Migration[2.3]
  milestone '19.1'

  def change
    create_table :user_permission_export_upload_upload_registry, id: :bigserial, if_not_exists: true do |t|
      t.bigint :user_permission_export_upload_upload_id, null: false
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

      t.index :user_permission_export_upload_upload_id,
        name: :idx_user_permission_export_upload_registry_on_upe_upload_id, unique: true
      t.index :retry_at,
        name: :idx_user_permission_export_upload_registry_on_retry_at
      t.index :state,
        name: :idx_user_permission_export_upload_registry_on_state
      # To optimize performance of UserPermissionExportUploadUploadRegistry.verification_failed_batch
      t.index :verification_retry_at,
        name: :idx_user_permission_export_upload_registry_failed_verification,
        order: "NULLS FIRST",
        where: "((state = 2) AND (verification_state = 3))"
      # To optimize performance of UserPermissionExportUploadUploadRegistry.needs_verification_count
      t.index :verification_state,
        name: :idx_user_permission_export_upload_registry_needs_verification,
        where: "((state = 2) AND (verification_state = ANY (ARRAY[0, 3])))"
      # To optimize performance of UserPermissionExportUploadUploadRegistry.verification_pending_batch
      t.index :verified_at,
        name: :idx_user_permission_export_upload_registry_pending_verification,
        order: "NULLS FIRST",
        where: "((state = 2) AND (verification_state = 0))"
    end
  end
end
