# frozen_string_literal: true

module API
  module Entities
    class RelatedEpic < ::API::Entities::Epic
      expose :related_epic_link_id, documentation: { type: 'Integer', format: 'int64', example: 1 }
      expose :epic_link_type, as: :link_type, documentation: { type: 'String', example: 'relates_to' }
      expose :related_epic_link_created_at, as: :link_created_at,
        documentation: { type: 'DateTime', example: '2022-01-31T15:10:45.080Z' }
      expose :related_epic_link_updated_at, as: :link_updated_at,
        documentation: { type: 'DateTime', example: '2022-01-31T15:10:45.080Z' }
    end
  end
end
