# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    module RelatedEpicLinks
      INSUFFICIENT_PERMISSIONS_MESSAGE = /could not be removed due to insufficient permissions/

      class DestroyService
        def initialize(legacy_epic_link, legacy_epic, current_user)
          @legacy_epic_link = legacy_epic_link
          @legacy_epic = legacy_epic
          @current_user = current_user
        end

        def execute
          item_ids = legacy_epic.work_item == work_item_source ? [work_item_target.id] : [work_item_source.id]

          ::WorkItems::RelatedWorkItemLinks::DestroyService
            .new(legacy_epic.work_item, current_user, { item_ids: item_ids })
            .execute
            .then { |result| transform_result(result) }
        end

        private

        def work_item_source
          legacy_epic_link.source.work_item
        end

        def work_item_target
          legacy_epic_link.target.work_item
        end

        def transform_result(result)
          if result[:message].match?(INSUFFICIENT_PERMISSIONS_MESSAGE) || result[:http_status] == 403
            result[:message] = 'No Related Epic Link found'
            result[:http_status] = :not_found
          end

          result[:message] = 'Relation was removed' if result[:status] == :success

          result
        end

        attr_reader :legacy_epic_link, :legacy_epic, :current_user
      end
    end
  end
end
