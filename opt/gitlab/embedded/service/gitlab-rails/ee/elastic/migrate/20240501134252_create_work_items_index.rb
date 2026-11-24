# frozen_string_literal: true

class CreateWorkItemsIndex < Elastic::Migration
  include ::Search::Elastic::MigrationCreateIndexHelper

  retry_on_failure

  def document_type
    :work_item
  end

  def target_class
    WorkItem
  end
end

CreateWorkItemsIndex.prepend ::Search::Elastic::MigrationObsolete
