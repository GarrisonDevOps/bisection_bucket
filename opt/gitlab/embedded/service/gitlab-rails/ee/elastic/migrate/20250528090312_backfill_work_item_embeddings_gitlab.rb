# frozen_string_literal: true

class BackfillWorkItemEmbeddingsGitlab < Elastic::Migration
  include ::Search::Elastic::MigrationBackfillHelper

  skip_if -> { !Gitlab::Saas.feature_available?(:ai_vertex_embeddings) }

  # expected run time: 18 hours
  batched!
  batch_size 200
  throttle_delay 1.minute
  space_requirements!

  DOCUMENT_TYPE = WorkItem
  PROJECT_IDS = [278964].freeze # https://gitlab.com/gitlab-org/gitlab
  SPACE_CALCULATION_MULTIPLIER = 768 * 4 # 768 (dimensions) x 4 bytes (each embedding is a float)

  def field_name
    'embedding_1'
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
        filter: project_filter,
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

  def build_reference(document_type, id, _es_id, es_parent)
    Search::Elastic::References::Embedding.new(document_type, id, es_parent)
  end

  def bookkeeping_service
    Search::Elastic::ProcessEmbeddingBookkeepingService
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

  def space_required_bytes
    return 0 if projects.none?

    remaining_documents_count * SPACE_CALCULATION_MULTIPLIER
  end
end

BackfillWorkItemEmbeddingsGitlab.prepend ::Search::Elastic::MigrationObsolete
