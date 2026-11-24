# frozen_string_literal: true

module TestHooks
  class GroupService < TestHooks::BaseService
    def execute
      enforcer = ::Gitlab::IpRestriction::Enforcer.new(@hook.group)
      unless enforcer.allows_current_ip?
        return ServiceResponse.error(
          message: 'Group access restricted by IP address.',
          reason: :forbidden
        )
      end

      project = find_project_for_trigger
      return error(project_not_found_error_message) unless project

      service = TestHooks::ProjectService.new(hook, current_user, @trigger || 'push_events')
      service.project = project
      service.execute
    end

    private

    def find_project_for_trigger
      if @trigger == 'vulnerability_events'
        @hook.group.vulnerability_reads.unarchived.order(:vulnerability_id).first&.project # rubocop:disable CodeReuse/ActiveRecord -- Specific use case for this service
      else
        @hook.group.first_non_empty_project
      end
    end

    def project_not_found_error_message
      if @trigger == 'vulnerability_events'
        s_('TestHooks|Ensure the group has a project with vulnerabilities.')
      else
        s_('TestHooks|Ensure the group has a project with commits.')
      end
    end
  end
end
