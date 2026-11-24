# frozen_string_literal: true

class RemoveCorrectWorkItemTypeIdFromWorkItemSecondAttempt < Elastic::Migration
  include ::Search::Elastic::MigrationRemoveFieldsHelper

  batched!
  throttle_delay 1.minute

  DOCUMENT_TYPE = WorkItem

  private

  def field_to_remove
    'correct_work_item_type_id'
  end
end

RemoveCorrectWorkItemTypeIdFromWorkItemSecondAttempt.prepend ::Search::Elastic::MigrationObsolete
