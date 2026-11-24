# frozen_string_literal: true

class ReindexWorkItemsToRemoveNotesFields < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[WorkItem]
  end
end

ReindexWorkItemsToRemoveNotesFields.prepend ::Search::Elastic::MigrationObsolete
