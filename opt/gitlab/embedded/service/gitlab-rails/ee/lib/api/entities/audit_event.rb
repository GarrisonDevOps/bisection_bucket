# frozen_string_literal: true

module API
  module Entities
    class AuditEvent < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64' }
      expose :author_id, documentation: { type: 'Integer', format: 'int64' }
      expose :entity_id, documentation: { type: 'Integer', format: 'int64' }
      expose :entity_type, documentation: { type: 'String' }
      expose :event_name, documentation: { type: 'String' } do |audit_event|
        audit_event.details.fetch :event_name, nil
      end
      expose :details, documentation: { type: 'Hash' } do |audit_event, _options|
        audit_event.formatted_details
      end
      expose :created_at, documentation: { type: 'DateTime' }
    end
  end
end
