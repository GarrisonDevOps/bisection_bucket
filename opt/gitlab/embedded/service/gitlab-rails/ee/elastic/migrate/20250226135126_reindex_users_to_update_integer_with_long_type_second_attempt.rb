# frozen_string_literal: true

class ReindexUsersToUpdateIntegerWithLongTypeSecondAttempt < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[User]
  end
end

ReindexUsersToUpdateIntegerWithLongTypeSecondAttempt.prepend ::Search::Elastic::MigrationObsolete
