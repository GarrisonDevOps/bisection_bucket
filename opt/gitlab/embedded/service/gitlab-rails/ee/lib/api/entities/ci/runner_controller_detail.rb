# frozen_string_literal: true

module API
  module Entities
    module Ci
      class RunnerControllerDetail < RunnerController
        expose :connected, documentation: {
          type: 'Boolean', example: true,
          desc: 'If `true`, the runner controller is connected. A runner controller is connected when it has used ' \
            'at least one of its active tokens within the last hour.'
        } do |controller, _options|
          controller.connected?
        end
      end
    end
  end
end
