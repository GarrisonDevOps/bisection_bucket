# frozen_string_literal: true

class BackfillWorkItemsEmbeddings < Elastic::Migration
  include ::Search::Elastic::MigrationBackfillHelper

  skip_if -> { !Gitlab::Saas.feature_available?(:ai_vertex_embeddings) }

  # expected run time: 9 hours
  batched!
  batch_size 200
  throttle_delay 1.minute
  space_requirements!

  DOCUMENT_TYPE = WorkItem
  RECENCY_PERIOD = 1.year
  PROJECT_IDS = [278964].freeze # https://gitlab.com/gitlab-org/gitlab
  SPACE_CALCULATION_MULTIPLIER = 768 * 4 # 768 (dimensions) x 4 bytes (each embedding is a float)

  def field_name
    'embedding_0'
  end

  def completed?
    return true if projects.none?

    super
  end

  def missing_field_filter
    {
      bool: {
        minimum_should_match: 1,
        should: fields_exist_query,
        filter: [
          project_filter,
          date_filter
        ],
        must: {
          term: {
            type: {
              value: DOCUMENT_TYPE.es_type
            }
          }
        }
      }
    }
  end

  def process_batch!
    body = {
      size: query_batch_size,
      query: {
        bool: {
          filter: missing_field_filter
        }
      }
    }

    results = client.search(index: index_name, body: body)
    hits = results.dig('hits', 'hits') || []

    embedding_references = hits.map! do |hit|
      id = hit.dig('_source', 'id')
      routing = hit['_routing']

      Search::Elastic::References::Embedding.new(DOCUMENT_TYPE, id, routing)
    end

    embedding_references.each_slice(update_batch_size) do |refs|
      Search::Elastic::ProcessEmbeddingBookkeepingService.track!(*refs)
    end

    embedding_references
  end

  def project_filter
    { bool: { should: project_shoulds, minimum_should_match: 1 } }
  end

  def project_shoulds
    projects.map do |project|
      { term: { project_id: project.id } }
    end
  end

  def projects
    []
  end

  def date_filter
    { range: { updated_at: { gte: RECENCY_PERIOD.ago.strftime('%Y-%m') } } }
  end

  def index_name
    Search::Elastic::Types::WorkItem.index_name
  end

  def space_required_bytes
    return 0 if projects.none?

    remaining_documents_count * SPACE_CALCULATION_MULTIPLIER
  end
end

BackfillWorkItemsEmbeddings.prepend ::Search::Elastic::MigrationObsolete
