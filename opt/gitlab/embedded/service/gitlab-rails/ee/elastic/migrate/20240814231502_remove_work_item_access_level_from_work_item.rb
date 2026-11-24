# frozen_string_literal: true

class RemoveWorkItemAccessLevelFromWorkItem < Elastic::Migration
  include ::Search::Elastic::MigrationRemoveFieldsHelper

  batched!
  throttle_delay 1.minute

  private

  def index_name
    ::Search::Elastic::References::WorkItem.index
  end

  def document_type
    'work_item'
  end

  def field_to_remove
    'work_item_access_level'
  end
end

RemoveWorkItemAccessLevelFromWorkItem.prepend ::Search::Elastic::MigrationObsolete
