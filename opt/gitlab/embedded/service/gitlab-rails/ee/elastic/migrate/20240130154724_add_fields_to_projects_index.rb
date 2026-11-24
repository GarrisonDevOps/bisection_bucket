# frozen_string_literal: true

class AddFieldsToProjectsIndex < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = Project

  private

  def new_mappings
    {
      mirror: {
        type: 'boolean'
      },
      owner_id: {
        type: 'integer'
      },
      forked: {
        type: 'boolean'
      },
      repository_languages: {
        type: 'keyword'
      }
    }
  end
end

AddFieldsToProjectsIndex.prepend ::Search::Elastic::MigrationObsolete
