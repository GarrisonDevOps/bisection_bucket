# frozen_string_literal: true

module EE
  module API
    module Todos
      extend ActiveSupport::Concern

      prepended do
        helpers do
          extend ::Gitlab::Utils::Override

          def authorize_can_read!
            authorize!(:read_epic, user_group)
          end
        end

        resource :groups, requirements: ::API::NAMESPACE_OR_PROJECT_REQUIREMENTS do
          desc 'Create a to-do item for an epic' do
            detail 'Creates a to-do item for the current user on a specified epic. If a to-do item already exists ' \
              'for the user on that epic, status code 304 is returned.'
            success ::API::Entities::Todo
            tags ['epics']
          end
          params do
            requires :id, type: String, desc: 'ID or URL-encoded path of the group.'
            requires :epic_iid, type: Integer, desc: 'Internal ID of the epic.'
          end
          route_setting :tier, :premium
          route_setting :authorization, permissions: :create_todo, boundary_type: :group
          post ":id/epics/:epic_iid/todo" do
            authorize_can_read!
            epic = find_group_epic(params[:epic_iid])
            todo = ::TodoService.new.mark_todo(epic, current_user).first

            if todo
              present todo, with: ::API::Entities::Todo, current_user: current_user
            else
              not_modified!
            end
          end
        end
      end
    end
  end
end
