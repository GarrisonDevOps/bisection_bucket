# frozen_string_literal: true

class IndexAllProjects < Elastic::Migration
  include ::Search::Elastic::MigrationDatabaseBackfillHelper

  batch_size 50_000
  batched!
  throttle_delay 1.minute
  retry_on_failure
  space_requirements!

  DOCUMENT_TYPE = Project

  def respect_limited_indexing?
    false
  end

  def space_required_bytes
    return 0 unless ::Gitlab::CurrentSettings.elasticsearch_limit_indexing?

    total_projects_in_database = Project.count
    index_size_in_bytes = helper.index_size_bytes(index_name: DOCUMENT_TYPE.index_name)
    projects_in_index = helper.documents_count(index_name: DOCUMENT_TYPE.index_name)
    total_projects_to_be_added = total_projects_in_database - projects_in_index
    average_bytes_per_project = index_size_in_bytes / projects_in_index
    total_projects_to_be_added * average_bytes_per_project
  rescue ZeroDivisionError
    0
  end
end

IndexAllProjects.prepend ::Search::Elastic::MigrationObsolete
