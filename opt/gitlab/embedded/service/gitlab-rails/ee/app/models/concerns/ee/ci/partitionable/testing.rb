# frozen_string_literal: true

module EE
  module Ci
    module Partitionable
      module Testing
        extend ActiveSupport::Concern

        PARTITIONABLE_EE_MODELS = %w[
          Geo::JobArtifactState
          Geo::PipelineArtifactState
        ].freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          override :partitionable_models

          def partitionable_models
            super + PARTITIONABLE_EE_MODELS
          end
        end
      end
    end
  end
end
