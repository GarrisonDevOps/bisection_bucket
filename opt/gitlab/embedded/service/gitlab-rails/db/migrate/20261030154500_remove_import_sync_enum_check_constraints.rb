# frozen_string_literal: true

class RemoveImportSyncEnumCheckConstraints < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  CONSTRAINTS = [
    [:import_sync_repositories, 'chk_import_sync_repositories_provider', 'provider = 0'],
    [:import_sync_repositories, 'chk_import_sync_repositories_authority_state', 'authority_state BETWEEN 0 AND 6'],
    [:import_sync_repositories, 'chk_import_sync_repositories_disconnect_reason',
      'disconnect_reason IS NULL OR disconnect_reason BETWEEN 0 AND 9'],
    [:import_sync_repository_states, 'chk_import_sync_repository_states_domain', 'domain BETWEEN 0 AND 2'],
    [:import_sync_repository_states, 'chk_import_sync_repository_states_state', 'state BETWEEN 0 AND 6'],
    [:import_sync_external_objects, 'chk_import_sync_external_objects_kind', 'kind BETWEEN 0 AND 4']
  ].freeze

  def up
    CONSTRAINTS.each do |table, name, _check|
      remove_check_constraint table, name
    end
  end

  def down
    CONSTRAINTS.each do |table, name, check|
      add_check_constraint table, check, name
    end
  end
end
