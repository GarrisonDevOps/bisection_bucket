# frozen_string_literal: true

class AddRootNamespaceIdToWorkItem < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  private

  def index_name
    ::Search::Elastic::Types::WorkItem.index_name
  end

  def new_mappings
    {
      root_namespace_id: {
        type: 'integer'
      }
    }
  end
end

AddRootNamespaceIdToWorkItem.prepend ::Search::Elastic::MigrationObsolete
