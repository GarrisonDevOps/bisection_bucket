# frozen_string_literal: true

class ReindexUserToFixUsernameAndNameAnalyzers < Elastic::Migration
  include ::Search::Elastic::MigrationReindexTaskHelper

  def targets
    %w[User]
  end
end

ReindexUserToFixUsernameAndNameAnalyzers.prepend ::Search::Elastic::MigrationObsolete
