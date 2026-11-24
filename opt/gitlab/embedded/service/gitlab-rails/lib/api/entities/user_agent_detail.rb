# frozen_string_literal: true

module API
  module Entities
    class UserAgentDetail < Grape::Entity
      expose :user_agent, documentation: {
        type: 'String', example: 'AppleWebKit/537.36', desc: 'User agent string of the client that created the item.'
      }
      expose :ip_address,
        documentation: { type: 'String', example: '127.0.0.1', desc: 'IP address of the client that created the item.' }
      expose :submitted, as: :akismet_submitted, documentation: {
        type: 'Boolean', example: false, desc: 'If `true`, the details were submitted to Akismet for spam detection.'
      }
    end
  end
end
