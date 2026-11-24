# frozen_string_literal: true

module API
  module Entities
    module Security
      module DependencyFirewall
        class PackageEvaluation < Grape::Entity
          expose :outcome, documentation: { type: 'String', example: 'blocked',
                                            values: %w[allowed warned blocked] }
          expose :reason, documentation: { type: 'String',
                                           example: "Package 'lodash' violates 'deny-mit' policy" }
        end
      end
    end
  end
end
