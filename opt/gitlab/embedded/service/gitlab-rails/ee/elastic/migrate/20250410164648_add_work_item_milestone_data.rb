# frozen_string_literal: true

class AddWorkItemMilestoneData < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = WorkItem

  private

  def index_name
    Search::Elastic::Types::WorkItem.index_name
  end

  def new_mappings
    {
      milestone_title: {
        type: 'keyword'
      },
      milestone_id: {
        type: 'long'
      }
    }
  end
end

AddWorkItemMilestoneData.prepend ::Search::Elastic::MigrationObsolete
