# frozen_string_literal: true

class BackfillTraversalIdsOnCommits < Elastic::Migration
  include ::Search::Elastic::MigrationProjectScopedUpdateByQueryHelper

  batched!
  batch_size 10_000
  throttle_delay 5.seconds
  retry_on_failure

  def index_name
    ::Elastic::Latest::CommitConfig.index_name
  end

  private

  def field_name
    'traversal_ids'
  end

  def document_type_value
    'commit'
  end

  def update_script(project)
    {
      source: "ctx._source.traversal_ids = params.traversal_ids",
      params: {
        traversal_ids: project.namespace_ancestry
      }
    }
  end

  # Enable batch processing in speed mode
  # Uses project data to build a lookup map for all projects in the batch
  def batch_update_script(projects)
    # Build map of project_id => traversal_ids from database
    # Convert project IDs to strings to match rid keyword field in Elasticsearch
    project_values = projects.index_by { |p| p.id.to_s }.transform_values(&:namespace_ancestry)

    {
      source: "ctx._source.traversal_ids = params.project_values[ctx._source.rid.toString()]",
      params: { project_values: project_values }
    }
  end

  # rubocop:disable CodeReuse/ActiveRecord -- Need to query database to identify and remove orphaned projects
  def search_projects_with_counts(exclude_project_ids:)
    projects_with_counts = super

    return projects_with_counts if projects_with_counts.empty?

    # Find and delete orphaned commits BEFORE backfilling
    all_project_ids = projects_with_counts.keys
    existing_project_ids = project_relation.id_in(all_project_ids).pluck(:id)
    orphaned_ids = all_project_ids - existing_project_ids

    if orphaned_ids.any?
      log('Deleting orphaned commits before backfill', orphaned_project_count: orphaned_ids.size)
      delete_commits_for_projects(orphaned_ids)

      # Remove orphaned projects from the counts hash since they've been deleted
      orphaned_ids.each { |id| projects_with_counts.delete(id) }
    end

    projects_with_counts
  end
  # rubocop:enable CodeReuse/ActiveRecord

  def delete_commits_for_projects(project_ids)
    return if project_ids.empty?

    response = client.delete_by_query(
      index: index_name,
      conflicts: 'proceed',
      wait_for_completion: true,
      timeout: ELASTIC_TIMEOUT,
      refresh: true,
      body: {
        query: {
          bool: {
            filter: [
              { term: { type: 'commit' } },
              { terms: { rid: project_ids } }
            ]
          }
        }
      }
    )

    log_raise 'Failed to delete orphaned commits', failures: response['failures'] if response['failures'].present?

    log('Successfully deleted orphaned commits', deleted_count: response['deleted'])
  end
end

BackfillTraversalIdsOnCommits.prepend ::Search::Elastic::MigrationObsolete
