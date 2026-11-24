# frozen_string_literal: true

module Registrations
  class StandardNamespaceCreateService < BaseNamespaceCreateService
    def initialize(user, group_params:, project_params:)
      super(user, group_params: group_params)

      @project_params = project_params.dup
    end

    def execute
      if new_group?
        create_with_new_group_flow
      else
        @group = Group.find_by_id(existing_group_id)

        create_project_flow
      end
    end

    private

    attr_reader :project_params

    def new_group?
      !existing_group_id
    end

    def existing_group_id
      group_params[:id]
    end

    def create_with_new_group_flow
      response = Groups::CreateService.new(user, modified_group_params).execute
      @group = response[:group]

      if response.success?
        after_successful_group_creation(group_track_action: 'create_group')
        create_project_flow
      else
        @project = Project.new(project_params.except(:initialize_with_readme))

        ServiceResponse.error(message: 'Group failed to be created', payload: { group: group, project: project })
      end
    end

    def create_project_params
      project_params.merge(namespace_id: group.id, organization_id: group.organization_id)
    end

    def create_project_flow
      @project = ::Projects::CreateService.new(user, create_project_params).execute
      if project.persisted?
        Gitlab::Tracking.event(self.class.name, 'create_project', namespace: project.namespace, user: user)

        ServiceResponse.success(payload: { project: project })
      else
        ServiceResponse.error(message: 'Project failed to be created', payload: { group: group, project: project })
      end
    end
  end
end

Registrations::StandardNamespaceCreateService.prepend_mod
