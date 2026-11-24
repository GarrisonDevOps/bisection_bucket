# frozen_string_literal: true

module API
  module Entities
    module Ai
      module DuoWorkflows
        class Event < Grape::Entity
          expose :id, documentation: { type: 'Integer' }
          expose :correlation_id, documentation: { type: 'String' }
          expose :event_type, documentation: { type: 'String' }
          expose :event_status, documentation: { type: 'String' }
          expose :message, documentation: { type: 'String' }
        end
      end
    end
  end
end
