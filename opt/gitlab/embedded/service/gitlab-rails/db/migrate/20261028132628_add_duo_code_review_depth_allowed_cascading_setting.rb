# frozen_string_literal: true

class AddDuoCodeReviewDepthAllowedCascadingSetting < Gitlab::Database::Migration[2.4]
  milestone '19.6'
  disable_ddl_transaction!

  include Gitlab::Database::MigrationHelpers::CascadingNamespaceSettings

  def up
    add_cascading_namespace_setting :duo_code_review_depth_allowed, :boolean, default: true, null: false
  end

  def down
    remove_cascading_namespace_setting :duo_code_review_depth_allowed
  end
end
