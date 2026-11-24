# frozen_string_literal: true

class CreateProjectImportExportRelationExportUploadUploadRegistry < Gitlab::Database::Migration[2.3]
  milestone '19.0'

  def change
    # no-op to address https://gitlab.com/gitlab-com/gl-infra/production/-/work_items/2195
  end
end
