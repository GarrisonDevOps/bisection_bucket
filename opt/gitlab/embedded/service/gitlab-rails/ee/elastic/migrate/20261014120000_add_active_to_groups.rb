# frozen_string_literal: true

class AddActiveToGroups < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Group

  private

  def new_mappings
    {
      active: {
        type: 'boolean'
      }
    }
  end
end
