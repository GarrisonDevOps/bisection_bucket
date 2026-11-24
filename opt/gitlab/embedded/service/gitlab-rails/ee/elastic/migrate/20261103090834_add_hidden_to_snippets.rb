# frozen_string_literal: true

class AddHiddenToSnippets < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Snippet

  private

  def new_mappings
    {
      hidden: {
        type: 'boolean'
      }
    }
  end
end
