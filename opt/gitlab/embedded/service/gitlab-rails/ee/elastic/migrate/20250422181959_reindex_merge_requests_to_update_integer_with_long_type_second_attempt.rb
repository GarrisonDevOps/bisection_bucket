# frozen_string_literal: true

class ReindexMergeRequestsToUpdateIntegerWithLongTypeSecondAttempt < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[MergeRequest]
  end
end

ReindexMergeRequestsToUpdateIntegerWithLongTypeSecondAttempt.prepend ::Search::Elastic::MigrationObsolete
