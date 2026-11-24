# frozen_string_literal: true

class AddOrganizationFieldsToGroups < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Group

  private

  # organization_id has been in the groups index mapping since the index was created.
  def new_mappings
    {
      organization_traversal_ids: {
        type: 'keyword'
      }
    }
  end
end
