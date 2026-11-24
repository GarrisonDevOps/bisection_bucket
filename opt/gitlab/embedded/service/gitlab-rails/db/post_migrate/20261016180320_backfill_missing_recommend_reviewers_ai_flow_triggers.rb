# frozen_string_literal: true

class BackfillMissingRecommendReviewersAiFlowTriggers < Gitlab::Database::Migration[2.4]
  disable_ddl_transaction!
  restrict_gitlab_migration gitlab_schema: :gitlab_main_org

  milestone '19.6'

  FLOW_REFERENCE = 'recommend_reviewers/v1'
  # Same values as SyncFoundationalFlowsService#build_trigger_params. {6} is
  # Ai::FlowTrigger::EVENT_TYPES[:merge_request] and kind 0 is ItemConsumer kind :direct.
  DESCRIPTION_PREFIX = 'Foundational flow trigger for '
  MERGE_REQUEST_FILTER = {
    'merge_request' => {
      'rules' => [
        { 'field' => 'action', 'operator' => 'in', 'value' => ['created'] }
      ]
    }
  }.freeze
  BATCH_SIZE = 1_000

  # The flow had no trigger when it was first released, so projects that enabled it then
  # have a consumer but no trigger. Create the trigger that provisioning creates today.
  def up
    item_ids = define_batchable_model('ai_catalog_items')
      .where(foundational_flow_reference: FLOW_REFERENCE)
      .pluck(:id)
    return if item_ids.empty?

    # Batches one item at a time so each_batch walks tmp_idx_ai_catalog_item_consumers_on_item_id_and_id.
    item_ids.each do |item_id|
      define_batchable_model('ai_catalog_item_consumers')
        .where(ai_catalog_item_id: item_id)
        .each_batch(of: BATCH_SIZE) do |batch|
          backfill(batch.pluck(:id))
        end
    end
  end

  def down
    # no-op: the triggers match what provisioning creates for the flow
  end

  private

  # A project can have duplicate consumers of the same item, so it gets one trigger, on the oldest
  # consumer, and none when any of its consumers already has one.
  def backfill(ids)
    execute(<<~SQL)
      INSERT INTO ai_flow_triggers
        (project_id, ai_catalog_item_consumer_id, description, event_types, filter, created_at, updated_at)
      SELECT DISTINCT ON (consumers.project_id, consumers.ai_catalog_item_id)
        consumers.project_id, consumers.id, #{quote(DESCRIPTION_PREFIX)} || items.name,
        '{6}', #{quote(MERGE_REQUEST_FILTER.to_json)}::jsonb, NOW(), NOW()
      FROM ai_catalog_item_consumers consumers
      INNER JOIN ai_catalog_items items ON items.id = consumers.ai_catalog_item_id
      LEFT JOIN ai_catalog_item_consumers parents ON parents.id = consumers.parent_item_consumer_id
      WHERE consumers.id IN (#{ids.join(',')})
        AND consumers.project_id IS NOT NULL
        AND consumers.kind = 0
        AND COALESCE(consumers.service_account_id, parents.service_account_id) IS NOT NULL
        AND NOT EXISTS (
          SELECT 1
          FROM ai_flow_triggers
          INNER JOIN ai_catalog_item_consumers siblings
            ON siblings.id = ai_flow_triggers.ai_catalog_item_consumer_id
          WHERE ai_flow_triggers.project_id = consumers.project_id
            AND siblings.ai_catalog_item_id = consumers.ai_catalog_item_id
            AND ai_flow_triggers.event_types @> '{6}'
        )
      ORDER BY consumers.project_id, consumers.ai_catalog_item_id, consumers.id
    SQL
  end

  def quote(value)
    connection.quote(value)
  end
end
