# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    module EpicLinks
      class DestroyService < BaseService
        include ::Gitlab::Utils::StrongMemoize

        def initialize(child_epic, user, _params = {})
          @child_epic = child_epic
          @current_user = user
        end

        def execute
          return not_found if child_epic.nil?
          return not_found if child_epic.work_item_parent_link.nil?

          ::WorkItems::ParentLinks::DestroyService.new(child_epic.work_item_parent_link, current_user)
            .execute
            .then { |result| transform_result(result) }
        end

        private

        attr_reader :child_epic, :current_user

        def not_found
          error("No Epic found for given params", 404)
        end

        def transform_result(result)
          return result if result[:status] == :success

          result[:message] = "No Epic found for given params" if result[:http_status] == 404

          result
        end
      end
    end
  end
end
