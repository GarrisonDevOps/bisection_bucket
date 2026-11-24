# frozen_string_literal: true

class ReindexNotesToUpdateIntegerWithLongTypeThirdAttempt < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[Note]
  end
end

ReindexNotesToUpdateIntegerWithLongTypeThirdAttempt.prepend ::Search::Elastic::MigrationObsolete
