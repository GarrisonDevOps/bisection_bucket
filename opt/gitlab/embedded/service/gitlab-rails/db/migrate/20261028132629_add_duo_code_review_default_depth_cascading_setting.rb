# frozen_string_literal: true

class AddDuoCodeReviewDefaultDepthCascadingSetting < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  include Gitlab::Database::MigrationHelpers::CascadingNamespaceSettings

  STANDARD_DEPTH = 0

  def up
    add_cascading_namespace_setting :duo_code_review_default_depth, :smallint, default: STANDARD_DEPTH, null: false
  end

  def down
    remove_cascading_namespace_setting :duo_code_review_default_depth
  end
end
