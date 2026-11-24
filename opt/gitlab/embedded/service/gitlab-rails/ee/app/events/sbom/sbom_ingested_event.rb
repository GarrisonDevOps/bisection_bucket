# frozen_string_literal: true

module Sbom
  class SbomIngestedEvent < ::Gitlab::EventStore::Event
    def schema
      {
        'type' => 'object',
        'properties' => {
          'pipeline_id' => { 'type' => 'integer' }
        },
        'required' => %w[pipeline_id]
      }
    end
  end
end
