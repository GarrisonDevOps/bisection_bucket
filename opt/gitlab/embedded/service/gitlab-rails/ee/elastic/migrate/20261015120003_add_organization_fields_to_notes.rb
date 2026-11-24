# frozen_string_literal: true

class AddOrganizationFieldsToNotes < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Note

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
