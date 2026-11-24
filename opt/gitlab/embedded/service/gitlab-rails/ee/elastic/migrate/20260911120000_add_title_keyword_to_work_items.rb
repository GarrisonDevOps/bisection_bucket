# frozen_string_literal: true

class AddTitleKeywordToWorkItems < Elastic::Migration
  include ::Search::Elastic::MigrationUpdateMappingsHelper

  DOCUMENT_TYPE = WorkItem

  # MigrationUpdateMappingsHelper#completed? only compares top-level mapping keys, and `title`
  # already exists, so the shared implementation would report completed before the sub-field
  # was ever added. Check for the sub-field itself instead.
  def completed?
    helper.refresh_index(index_name: index_name)

    mappings = helper.get_mapping(index_name: index_name)

    mappings.dig('title', 'fields', 'keyword').present?
  end

  private

  def new_mappings
    {
      title: {
        type: 'text',
        index_options: 'positions',
        analyzer: 'title_analyzer',
        fields: {
          keyword: {
            type: 'keyword',
            normalizer: 'lower_case_normalizer',
            ignore_above: 1024
          }
        }
      }
    }
  end
end
