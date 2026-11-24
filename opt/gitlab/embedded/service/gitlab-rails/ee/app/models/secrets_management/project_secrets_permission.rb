# frozen_string_literal: true

module SecretsManagement
  class ProjectSecretsPermission < BaseSecretsPermission
    RESOURCE_TYPE = 'Project'

    def resource_type
      RESOURCE_TYPE
    end

    private

    def member_role_has_access_to_resource?(member_role)
      resource.namespace.self_and_ancestors.where(id: member_role.namespace_id).exists?
    end
  end
end
