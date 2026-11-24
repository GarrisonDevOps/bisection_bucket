# frozen_string_literal: true

module API
  module Entities
    module Geo
      class PipelineRefs < Grape::Entity
        expose :pipeline_refs, documentation: { type: 'String', is_array: true, example: ['refs/pipelines/1'] }
      end
    end
  end
end
