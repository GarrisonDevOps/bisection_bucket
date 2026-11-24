# frozen_string_literal: true

class AddOrganizationFieldsToMainIndex < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  def index_name
    Elastic::Latest::Config.index_name
  end

  private

  def new_mappings
    {
      organization_id: {
        type: 'long'
      },
      organization_traversal_ids: {
        type: 'keyword'
      }
    }
  end
end
