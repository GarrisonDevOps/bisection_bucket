# frozen_string_literal: true

class IndexWorkItemsMilestoneState < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = WorkItem

  private

  def index_name
    Search::Elastic::Types::WorkItem.index_name
  end

  def new_mappings
    {
      milestone_state: {
        type: 'keyword'
      }
    }
  end
end

IndexWorkItemsMilestoneState.prepend ::Search::Elastic::MigrationObsolete
