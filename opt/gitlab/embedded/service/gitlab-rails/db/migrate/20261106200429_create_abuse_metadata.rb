# frozen_string_literal: true

class CreateAbuseMetadata < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    create_table :abuse_metadata, id: false do |t|
      t.bigint :user_id, primary_key: true, default: nil
      t.timestamps_with_timezone null: false
      t.jsonb :metadata, null: false, default: {}

      t.foreign_key :users, column: :user_id, on_delete: :cascade
      t.check_constraint 'octet_length(metadata::text) <= 65536', name: 'check_abuse_metadata_metadata_size'
    end
  end
end
