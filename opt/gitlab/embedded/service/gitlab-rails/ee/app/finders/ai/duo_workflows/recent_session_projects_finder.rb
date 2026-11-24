# frozen_string_literal: true

module Ai
  module DuoWorkflows
    class RecentSessionProjectsFinder
      MAX_PROJECTS = 50

      def initialize(current_user:, limit: MAX_PROJECTS)
        @current_user = current_user
        @limit = limit
      end

      def execute
        return ::Project.none unless current_user

        project_ids = ::Ai::DuoWorkflows::Workflow.recent_session_project_ids_for_user(current_user.id, limit: limit)

        ::Project.id_in_ordered(project_ids)
          .public_or_visible_to_user(current_user)
          .with_route
          .with_namespace
      end

      private

      attr_reader :current_user, :limit
    end
  end
end
