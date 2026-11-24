# frozen_string_literal: true

class AddTraversalIdsToNotes < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Note

  private

  def new_mappings
    {
      traversal_ids: {
        type: 'keyword'
      }
    }
  end
end

AddTraversalIdsToNotes.prepend ::Search::Elastic::MigrationObsolete
