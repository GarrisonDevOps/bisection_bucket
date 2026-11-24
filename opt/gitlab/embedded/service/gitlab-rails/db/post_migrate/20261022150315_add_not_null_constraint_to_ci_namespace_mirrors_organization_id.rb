# frozen_string_literal: true

class AddNotNullConstraintToCiNamespaceMirrorsOrganizationId < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  disable_ddl_transaction!

  DEPENDENT_BATCHED_BACKGROUND_MIGRATIONS = ["20260922092735"]

  def up
    add_not_null_constraint :ci_namespace_mirrors, :organization_id, validate: false
  end

  def down
    remove_not_null_constraint :ci_namespace_mirrors, :organization_id
  end
end
