# frozen_string_literal: true

module API
  module Entities
    module Clusters
      class AgentUrlConfiguration < Grape::Entity
        expose :id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        expose :agent_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
        expose :url, documentation: { type: 'String' }
        expose :public_key, documentation: { type: 'String' }
        expose :client_cert, documentation: { type: 'String' }
        expose :ca_cert, documentation: { type: 'String' }
        expose :tls_host, documentation: { type: 'String' }

        def public_key
          return unless object.public_key

          Base64.strict_encode64(object.public_key)
        end
      end
    end
  end
end
