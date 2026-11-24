# frozen_string_literal: true

module Vulnerabilities
  class ScheduleRemovingAllFromProjectService
    def initialize(projects, resolved_on_default_branch)
      @projects = projects
      @resolved_on_default_branch = resolved_on_default_branch
    end

    def execute
      return wrong_arguments_response unless projects.all?(::Project)

      bulk_schedule_jobs!

      scheduling_successful_response
    end

    private

    attr_reader :projects, :resolved_on_default_branch

    def wrong_arguments_response
      ServiceResponse.error(
        message: 'This worker accepts an array of Projects',
        reason: :argument_error
      )
    end

    def bulk_schedule_jobs!
      Vulnerabilities::RemoveAllVulnerabilitiesWorker.bulk_perform_async_with_contexts(
        projects,
        arguments_proc: ->(project) { [project.id, filter_params] },
        context_proc: ->(project) { { project: project } }
      )
    end

    def filter_params
      {
        resolved_on_default_branch: resolved_on_default_branch
      }.stringify_keys
    end

    def scheduling_successful_response
      ServiceResponse.success(
        message: "Scheduled deletion of all Vulnerabilities for given projects",
        payload: { projects: projects }
      )
    end
  end
end
