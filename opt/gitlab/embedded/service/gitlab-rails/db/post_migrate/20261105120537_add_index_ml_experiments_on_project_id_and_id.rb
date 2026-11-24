# frozen_string_literal: true

class AddIndexMlExperimentsOnProjectIdAndId < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  TABLE_NAME = :ml_experiments
  INDEX_NAME = 'index_ml_experiments_on_project_id_and_id'

  def up
    add_concurrent_index TABLE_NAME, %i[project_id id], name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end
end
