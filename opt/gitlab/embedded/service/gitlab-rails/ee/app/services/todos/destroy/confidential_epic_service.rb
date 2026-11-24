# frozen_string_literal: true

module Todos
  module Destroy
    # Service class for deleting todos that belong to confidential epics.
    # It deletes todos for users that are not at least reporters.
    class ConfidentialEpicService < ::Todos::Destroy::BaseService
      extend ::Gitlab::Utils::Override

      attr_reader :epic

      def initialize(epic_id:)
        @epic = ::Epic.find_by_id(epic_id)
      end

      def execute
        return unless todos_to_remove?

        delete_todos
      end

      private

      def delete_todos
        authorized_users = epic.group.members_with_parents.non_guests.select(:user_id)

        todos.not_in_users(authorized_users).delete_all
      end

      def todos
        epic.todos
      end

      def todos_to_remove?
        epic&.confidential?
      end
    end
  end
end
