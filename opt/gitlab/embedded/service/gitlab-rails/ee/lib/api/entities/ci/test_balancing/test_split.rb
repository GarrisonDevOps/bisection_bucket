# frozen_string_literal: true

module API
  module Entities
    module Ci
      module TestBalancing
        class TestSplit < Grape::Entity
          expose :path, documentation: { type: 'String', example: 'spec/models/user_spec.rb' }
          expose :expected_duration, documentation: { type: 'Float', example: 12.5 }
        end
      end
    end
  end
end
