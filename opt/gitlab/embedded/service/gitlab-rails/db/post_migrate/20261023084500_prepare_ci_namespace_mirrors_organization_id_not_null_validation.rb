# frozen_string_literal: true

class PrepareCiNamespaceMirrorsOrganizationIdNotNullValidation < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  CONSTRAINT_NAME = 'check_f051ac59d0'

  def up
    prepare_async_check_constraint_validation :ci_namespace_mirrors, name: CONSTRAINT_NAME
  end

  def down
    unprepare_async_check_constraint_validation :ci_namespace_mirrors, name: CONSTRAINT_NAME
  end
end
