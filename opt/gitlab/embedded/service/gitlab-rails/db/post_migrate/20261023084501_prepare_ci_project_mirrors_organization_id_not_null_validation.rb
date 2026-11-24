# frozen_string_literal: true

class PrepareCiProjectMirrorsOrganizationIdNotNullValidation < Gitlab::Database::Migration[2.3]
  milestone '19.6'

  CONSTRAINT_NAME = 'check_eee95b5a5d'

  def up
    prepare_async_check_constraint_validation :ci_project_mirrors, name: CONSTRAINT_NAME
  end

  def down
    unprepare_async_check_constraint_validation :ci_project_mirrors, name: CONSTRAINT_NAME
  end
end
