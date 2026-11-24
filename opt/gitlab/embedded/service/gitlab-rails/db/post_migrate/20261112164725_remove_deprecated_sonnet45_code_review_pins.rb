# frozen_string_literal: true

class RemoveDeprecatedSonnet45CodeReviewPins < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  milestone '19.6'

  TARGET_FEATURE = 21 # review_merge_request_dap
  DEPRECATED_REFS = %w[
    claude_sonnet_4_5_20250929
    claude_sonnet_4_5_20250929_vertex
    claude_sonnet_4_5_20250929_bedrock
  ].freeze
  BATCH_SIZE = 1000

  def up
    model = define_batchable_model(:ai_namespace_feature_settings, connection: connection)

    model.each_batch(column: :id, of: BATCH_SIZE) do |relation|
      relation
        .where(feature: TARGET_FEATURE, offered_model_ref: DEPRECATED_REFS)
        .delete_all
    end
  end

  def down
    # No-op: these rows pinned a deprecated model and should not be recreated.
  end
end
