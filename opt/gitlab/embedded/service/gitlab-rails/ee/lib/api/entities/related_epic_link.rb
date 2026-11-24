# frozen_string_literal: true

module API
  module Entities
    class RelatedEpicLink < Grape::Entity
      expose :id, documentation: { type: 'Integer', format: 'int64', example: 123 }
      expose :source, as: :source_epic, using: ::API::Entities::Epic
      expose :target, as: :target_epic, using: ::API::Entities::Epic
      expose :link_type, documentation: { type: 'String', example: "relates_to" }
      expose :created_at, documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" }
      expose :updated_at, documentation: { type: 'DateTime', example: "2022-01-31T15:10:45.080Z" }

      def id
        case object
        when ::Epic::RelatedEpicLink
          object.id
        when ::WorkItems::RelatedWorkItemLink
          object.related_epic_link.id
        end
      end

      def source
        case object.source
        when ::Epic
          object.source
        when ::WorkItem
          object.source.synced_epic
        end
      end

      def target
        case object.target
        when ::Epic
          object.target
        when ::WorkItem
          object.target.synced_epic
        end
      end
    end
  end
end
