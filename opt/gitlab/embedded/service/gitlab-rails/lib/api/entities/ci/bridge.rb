# frozen_string_literal: true

module API
  module Entities
    module Ci
      class Bridge < JobBasic
        expose :downstream_pipeline, using: ::API::Entities::Ci::PipelineBasic,
          documentation: { type: 'API::Entities::Ci::PipelineBasic' }
      end
    end
  end
end
