# frozen_string_literal: true

module SecretsManagement
  module RequiresActiveNamespace
    extend ActiveSupport::Concern

    GROUP_INACTIVE_ERROR = 'You cannot perform write operations on an archived group or a group pending deletion.'
    PROJECT_INACTIVE_ERROR = 'You cannot perform write operations on an archived project or a project pending deletion.'

    private

    def raise_if_namespace_inactive!(namespace)
      if namespace.is_a?(Group)
        return if namespace.active?

        raise_resource_not_available_error!(GROUP_INACTIVE_ERROR)
      else
        return if namespace.self_and_ancestors_active?

        raise_resource_not_available_error!(PROJECT_INACTIVE_ERROR)
      end
    end
  end
end
