# frozen_string_literal: true

class UpdateCodeModelMetadata < ActiveContext::Migration[1.0]
  milestone '18.10'

  def migrate!
    update_collection_metadata(collection: collection, metadata: metadata)
  end

  def skip?
    ::Gitlab::AiGateway.has_self_hosted_ai_gateway?
  end

  def metadata
    model_metadata = { model_ref: 'text_embedding_005_vertex', field: 'embeddings_v1' }

    {
      current_indexing_embedding_model: model_metadata,
      search_embedding_model: model_metadata
    }
  end

  def collection
    Ai::ActiveContext::Collections::Code
  end
end
