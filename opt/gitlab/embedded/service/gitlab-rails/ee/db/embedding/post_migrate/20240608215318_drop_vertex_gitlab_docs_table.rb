# frozen_string_literal: true

class DropVertexGitlabDocsTable < Gitlab::Database::Migration[2.2]
  disable_ddl_transaction!
  milestone '17.1'

  INDEX_NAME = 'index_vertex_gitlab_docs_on_version_where_embedding_is_null'
  INDEX_NAME2 = 'index_vertex_gitlab_docs_on_version_and_metadata_source_and_id'

  def up
    return unless table_exists?(:vertex_gitlab_docs)

    drop_table :vertex_gitlab_docs
  end

  def down
    create_table :vertex_gitlab_docs do |t|
      t.timestamps_with_timezone null: false
      t.integer :version, default: 0, null: false
      t.vector :embedding, limit: 768
      t.text :url, null: false, limit: 2048
      t.text :content, null: false, limit: 32768
      t.jsonb :metadata, null: false
    end

    add_concurrent_index :vertex_gitlab_docs, :version, where: 'embedding IS NULL', name: INDEX_NAME
    disable_statement_timeout do
      execute <<~SQL
      CREATE INDEX CONCURRENTLY #{INDEX_NAME2}
      ON vertex_gitlab_docs
      USING BTREE (version, (metadata->>'source'), id)
      SQL
    end
  end
end
