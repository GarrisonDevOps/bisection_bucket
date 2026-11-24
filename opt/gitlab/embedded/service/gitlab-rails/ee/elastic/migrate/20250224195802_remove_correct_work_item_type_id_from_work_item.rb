# frozen_string_literal: true

class RemoveCorrectWorkItemTypeIdFromWorkItem < Elastic::Migration
  include ::Search::Elastic::MigrationRemoveFieldsHelper

  DOCUMENT_TYPE = WorkItem

  batched!
  throttle_delay 1.minute

  private

  def field_to_remove
    'correct_work_item_type_id'
  end
end

RemoveCorrectWorkItemTypeIdFromWorkItem.prepend ::Search::Elastic::MigrationObsolete
