# frozen_string_literal: true

module AuditEvents
  class ProjectAuditEventFinder < BaseAuditEventFinder
    def initialize(project:, params: {})
      super(params: params)
      @project = project
    end

    private

    def init_collection
      ::AuditEvents::ProjectAuditEvent.by_project(@project.id)
    end
  end
end
