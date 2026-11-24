# frozen_string_literal: true

class ReindexWikisToUpdateIntegerWithLongType < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[Wiki]
  end
end

ReindexWikisToUpdateIntegerWithLongType.prepend ::Search::Elastic::MigrationObsolete
