# frozen_string_literal: true

# Reversibility tested with db:migrate:down:main and db:migrate:up:main VERSION=20261112221109 on the test database.
class AddIndexMlExperimentsOnDeletedOnAndId < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!

  milestone '19.6'

  TABLE_NAME = :ml_experiments
  INDEX_NAME = 'index_ml_experiments_on_deleted_on_and_id'

  def up
    add_concurrent_index TABLE_NAME, %i[deleted_on id], where: 'deleted_on IS NOT NULL', name: INDEX_NAME
  end

  def down
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end
end
