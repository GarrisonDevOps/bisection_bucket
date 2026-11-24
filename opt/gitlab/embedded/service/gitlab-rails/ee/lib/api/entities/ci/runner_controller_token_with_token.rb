# frozen_string_literal: true

module API
  module Entities
    module Ci
      class RunnerControllerTokenWithToken < RunnerControllerToken
        expose :token, documentation: { type: 'String', desc: 'Token value used for authentication.' }
      end
    end
  end
end
