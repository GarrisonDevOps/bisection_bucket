# frozen_string_literal: true

class AddLabelIdsToMergeRequest < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = MergeRequest

  private

  def new_mappings
    { label_ids: { type: 'keyword' } }
  end
end

AddLabelIdsToMergeRequest.prepend ::Search::Elastic::MigrationObsolete
