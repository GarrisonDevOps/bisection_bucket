# frozen_string_literal: true

module WorkItems
  module LegacyEpics
    module EpicIssues
      class DestroyService < BaseService
        include ::Gitlab::Utils::StrongMemoize

        def initialize(link, user)
          @link = link
          @current_user = user
        end

        def execute
          parent_link = WorkItems::ParentLink.for_children(link.issue_id).first
          return error(not_found_error_message, 404) unless parent_link

          ::WorkItems::ParentLinks::DestroyService.new(parent_link, current_user)
            .execute
            .tap do |result|
              result[:message] = not_found_error_message if result[:http_status] == 404
            end
        end

        private

        def not_found_error_message
          "No Issue Link found"
        end

        attr_reader :link, :current_user
      end
    end
  end
end
