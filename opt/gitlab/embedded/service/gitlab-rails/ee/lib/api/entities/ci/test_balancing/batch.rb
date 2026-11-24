# frozen_string_literal: true

module API
  module Entities
    module Ci
      module TestBalancing
        class Batch < Grape::Entity
          expose :mode, expose_nil: false,
            documentation: { type: 'String', example: 'seed', values: %w[seed retry] }
          expose :test_splits, using: ::API::Entities::Ci::TestBalancing::TestSplit,
            documentation: { is_array: true }
        end
      end
    end
  end
end
