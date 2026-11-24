# frozen_string_literal: true

module API
  module Entities
    module Ci
      module JobRequest
        class Credentials < Grape::Entity
          expose :type, documentation: { type: 'String' }
          expose :url, documentation: { type: 'String' }
          expose :username, documentation: { type: 'String' }
          expose :password, documentation: { type: 'String' }
        end
      end
    end
  end
end
