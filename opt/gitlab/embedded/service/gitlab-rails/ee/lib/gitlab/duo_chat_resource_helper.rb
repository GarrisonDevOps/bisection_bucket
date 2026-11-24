# frozen_string_literal: true

module Gitlab
  module DuoChatResourceHelper
    def namespace
      case resource
      when Group
        resource
      when Project
        resource.group
      when User
        nil
      else
        case resource&.resource_parent
        when Group
          resource.resource_parent
        when Project
          resource.resource_parent.group
        end
      end
    end

    def project
      if resource.is_a?(Project)
        resource
      elsif resource.is_a?(Group) || resource.is_a?(User)
        nil
      elsif resource&.resource_parent.is_a?(Project)
        resource.resource_parent
      end
    end
  end
end
