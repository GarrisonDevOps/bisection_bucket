# frozen_string_literal: true

class ReindexMergeRequestsToUpdateIntegerWithLongType < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[MergeRequest]
  end
end

ReindexMergeRequestsToUpdateIntegerWithLongType.prepend ::Search::Elastic::MigrationObsolete
