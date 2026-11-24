# frozen_string_literal: true

class BackfillTraversalIdsOnMergeRequests < Elastic::Migration
  include ::Search::Elastic::MigrationBackfillHelper

  batched!
  batch_size 9_000
  throttle_delay 1.minute

  DOCUMENT_TYPE = MergeRequest

  private

  def field_name
    'traversal_ids'
  end
end

BackfillTraversalIdsOnMergeRequests.prepend ::Search::Elastic::MigrationObsolete
