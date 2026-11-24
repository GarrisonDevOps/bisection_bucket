# frozen_string_literal: true

module SecretsManagement
  module EnrollmentHelper
    def allow_secrets_manager_namespace_enrollment?(namespace)
      NamespaceEnrollment.enrollment_allowed?(namespace)
    end

    def allow_secrets_manager_instance_enrollment?
      InstanceEnrollment.enrollment_allowed?
    end

    def secrets_manager_available_for_group?(group)
      Availability.for_group?(group) && can?(current_user, :read_secrets_manager, group)
    end

    def secrets_manager_available_for_project?(project)
      Availability.for_project?(project) && can?(current_user, :read_project_secrets_manager, project)
    end
  end
end
