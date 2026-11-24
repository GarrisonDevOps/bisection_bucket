# frozen_string_literal: true

class AddExtraFieldsToWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = WorkItem

  private

  def index_name
    Search::Elastic::Types::WorkItem.index_name
  end

  def new_mappings
    {
      milestone_start_date: {
        type: 'date'
      },
      milestone_due_date: {
        type: 'date'
      },
      closed_at: {
        type: 'date'
      },
      weight: {
        type: 'integer'
      },
      health_status: {
        type: 'short'
      },
      label_names: {
        type: 'keyword'
      }
    }
  end
end

AddExtraFieldsToWorkItems.prepend ::Search::Elastic::MigrationObsolete
