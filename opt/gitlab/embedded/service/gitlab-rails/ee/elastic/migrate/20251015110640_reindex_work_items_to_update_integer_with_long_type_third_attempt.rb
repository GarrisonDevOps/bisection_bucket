# frozen_string_literal: true

class ReindexWorkItemsToUpdateIntegerWithLongTypeThirdAttempt < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[WorkItem]
  end
end

ReindexWorkItemsToUpdateIntegerWithLongTypeThirdAttempt.prepend ::Search::Elastic::MigrationObsolete
