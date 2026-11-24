# frozen_string_literal: true

class AddDuoCodeReviewDepthAllowedToProjectSettings < Gitlab::Database::Migration[2.4]
  milestone '19.6'

  def change
    add_column :project_settings, :duo_code_review_depth_allowed, :boolean, default: true, null: false
  end
end
