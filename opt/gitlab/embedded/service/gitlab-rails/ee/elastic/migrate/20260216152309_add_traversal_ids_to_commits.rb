# frozen_string_literal: true

class AddTraversalIdsToCommits < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  private

  def index_name
    Elastic::Latest::CommitConfig.index_name
  end

  def new_mappings
    {
      traversal_ids: {
        type: 'keyword'
      }
    }
  end
end

AddTraversalIdsToCommits.prepend ::Search::Elastic::MigrationObsolete
