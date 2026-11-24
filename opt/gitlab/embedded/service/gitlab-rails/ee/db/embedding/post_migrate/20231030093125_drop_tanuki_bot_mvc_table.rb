# frozen_string_literal: true

class DropTanukiBotMvcTable < Gitlab::Database::Migration[2.2]
  milestone '16.6'

  def up
    drop_table :tanuki_bot_mvc
  end

  def down
    create_table :tanuki_bot_mvc do |t|
      t.timestamps_with_timezone null: false
      t.integer :version, default: 0, null: false
      t.vector :embedding, limit: 1536, null: true
      t.text :url, null: false, limit: 2048
      t.text :content, null: false, limit: 32768
      t.jsonb :metadata, null: false
      t.text :chroma_id, index: { unique: true }, limit: 512
    end
  end
end
