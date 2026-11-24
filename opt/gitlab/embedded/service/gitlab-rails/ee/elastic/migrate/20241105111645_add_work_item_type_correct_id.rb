# frozen_string_literal: true

class AddWorkItemTypeCorrectId < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = WorkItem

  private

  def index_name
    Search::Elastic::Types::WorkItem.index_name
  end

  def new_mappings
    {
      correct_work_item_type_id: {
        type: 'long'
      }
    }
  end
end

AddWorkItemTypeCorrectId.prepend ::Search::Elastic::MigrationObsolete
