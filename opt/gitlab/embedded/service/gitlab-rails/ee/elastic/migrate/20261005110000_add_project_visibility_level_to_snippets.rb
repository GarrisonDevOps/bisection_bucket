# frozen_string_literal: true

class AddProjectVisibilityLevelToSnippets < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Snippet

  private

  def new_mappings
    {
      project_visibility_level: {
        type: 'short'
      }
    }
  end
end
