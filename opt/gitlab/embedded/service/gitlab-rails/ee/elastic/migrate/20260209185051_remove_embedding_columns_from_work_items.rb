# frozen_string_literal: true

class RemoveEmbeddingColumnsFromWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationRemoveFieldsHelper

  DOCUMENT_TYPE = WorkItem

  batched!
  throttle_delay 1.minute

  private

  def fields_to_remove
    %w[embedding_0 embedding_1]
  end
end

RemoveEmbeddingColumnsFromWorkItems.prepend ::Search::Elastic::MigrationObsolete
