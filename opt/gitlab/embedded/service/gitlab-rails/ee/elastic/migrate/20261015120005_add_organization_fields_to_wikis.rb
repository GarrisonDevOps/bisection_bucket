# frozen_string_literal: true

class AddOrganizationFieldsToWikis < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  def index_name
    Elastic::Latest::WikiConfig.index_name
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
