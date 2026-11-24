# frozen_string_literal: true

class AddUniqueIndexVoiIdPartitionId < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  milestone '19.6'

  TABLE_NAME = :vulnerability_occurrence_identifiers
  INDEX_NAME = 'index_vulnerability_occurrence_identifiers_on_id_partition_id'

  # Index was created asynchronously on GitLab.com in
  # https://gitlab.com/gitlab-org/gitlab/-/work_items/627925, so this is a no-op there.
  def up
    # rubocop:disable Migration/PreventIndexCreation -- https://gitlab.com/gitlab-org/database-team/team-tasks/-/work_items/681
    add_concurrent_index TABLE_NAME, %i[id partition_id], unique: true, name: INDEX_NAME
    # rubocop:enable Migration/PreventIndexCreation
  end

  def down
    remove_concurrent_index_by_name TABLE_NAME, INDEX_NAME
  end
end
