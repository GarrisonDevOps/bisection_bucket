# frozen_string_literal: true

class ReindexProjectsToUpdateIntegerWithLongTypeSecondAttempt < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[Project]
  end
end

ReindexProjectsToUpdateIntegerWithLongTypeSecondAttempt.prepend ::Search::Elastic::MigrationObsolete
