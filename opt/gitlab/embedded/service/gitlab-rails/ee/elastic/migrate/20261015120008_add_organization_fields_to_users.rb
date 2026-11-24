# frozen_string_literal: true

class AddOrganizationFieldsToUsers < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = User

  private

  def new_mappings
    {
      organization_id: {
        type: 'long'
      }
    }
  end
end
