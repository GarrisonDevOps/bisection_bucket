# frozen_string_literal: true

class RemoveNotesFieldsFromWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationRemoveFieldsHelper

  DOCUMENT_TYPE = WorkItem

  batched!
  throttle_delay 1.minute

  private

  def fields_to_remove
    %w[notes notes_internal]
  end
end

RemoveNotesFieldsFromWorkItems.prepend ::Search::Elastic::MigrationObsolete
