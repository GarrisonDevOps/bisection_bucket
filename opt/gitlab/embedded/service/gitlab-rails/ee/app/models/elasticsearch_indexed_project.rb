# frozen_string_literal: true

class ElasticsearchIndexedProject < ApplicationRecord
  include ElasticsearchIndexedContainer

  self.primary_key = :project_id

  belongs_to :project

  validates :project_id, presence: true, uniqueness: true

  def self.target_attr_name
    :project_id
  end

  private

  def index
    return unless Gitlab::CurrentSettings.elasticsearch_indexing?

    ::Elastic::ProcessInitialBookkeepingService.backfill_projects!(project) # rubocop: disable CodeReuse/ServiceClass
  end

  def delete_from_index
    return unless Gitlab::CurrentSettings.elasticsearch_indexing?

    # project documents are indexed regardless of limit settings
    ElasticDeleteProjectWorker.perform_async(project.id, project.es_id, 'delete_project' => false)
  end
end
