# frozen_string_literal: true

class AddDuoCodeReviewDefaultDepthToProjectSettings < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  STANDARD_DEPTH = 0

  def change
    add_column :project_settings, :duo_code_review_default_depth, :smallint, default: STANDARD_DEPTH, null: false
  end
end
