# frozen_string_literal: true

module Groups
  module VirtualRegistries
    class BaseController < Groups::ApplicationController
      include VirtualRegistryHelper

      before_action :ensure_feature!

      private

      def ensure_feature!
        render_404 unless ::VirtualRegistries::Packages::Maven.virtual_registry_available?(@group, current_user)
      end

      def verify_read_virtual_registry!
        access_denied! unless can?(current_user, :read_virtual_registry, @group.virtual_registry_policy_subject)
      end

      def verify_create_virtual_registry!
        access_denied! unless can_create_virtual_registry?(@group)
      end

      def verify_update_virtual_registry!
        access_denied! unless can?(current_user, :update_virtual_registry, @group.virtual_registry_policy_subject)
      end

      def verify_destroy_virtual_registry!
        access_denied! unless can_destroy_virtual_registry?(@group)
      end
    end
  end
end
