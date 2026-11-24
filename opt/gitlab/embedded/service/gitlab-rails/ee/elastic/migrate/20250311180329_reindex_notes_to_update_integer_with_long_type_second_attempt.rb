# frozen_string_literal: true

class ReindexNotesToUpdateIntegerWithLongTypeSecondAttempt < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[Note]
  end
end

ReindexNotesToUpdateIntegerWithLongTypeSecondAttempt.prepend ::Search::Elastic::MigrationObsolete
