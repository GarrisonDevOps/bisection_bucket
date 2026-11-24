# frozen_string_literal: true

class SetDefaultChunkStrategy < ActiveContext::Migration[1.0]
  milestone '19.1'

  def migrate!
    collection_record = collection.collection_record
    return if collection_record.chunk_strategy.present?

    # Call update! directly to bypass the update_options! immutability guard,
    # which is appropriate for this one-time migration operation.
    collection_record.update!(
      options: collection_record.options.merge(
        chunk_strategy: 'code_bytes',
        chunk_strategy_size: 1000
      )
    )
  end

  def skip?
    ::Gitlab::AiGateway.has_self_hosted_ai_gateway?
  end

  def collection
    Ai::ActiveContext::Collections::Code
  end
end
