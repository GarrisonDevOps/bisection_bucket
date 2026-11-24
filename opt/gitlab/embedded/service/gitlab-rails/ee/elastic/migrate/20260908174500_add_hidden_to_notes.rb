# frozen_string_literal: true

class AddHiddenToNotes < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Note

  private

  def new_mappings
    {
      hidden: {
        type: 'boolean'
      }
    }
  end
end
