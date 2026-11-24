# frozen_string_literal: true

class BackfillTraversalIdsForMilestones < Elastic::Migration
  include ::Search::Elastic::MigrationBackfillHelper

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = Milestone

  private

  def field_name
    :traversal_ids
  end
end

BackfillTraversalIdsForMilestones.prepend ::Search::Elastic::MigrationObsolete
