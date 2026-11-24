# frozen_string_literal: true

module Groups
  module VirtualRegistries
    class ContainerController < Groups::ApplicationController
      before_action :ensure_feature!, only: [:index]
      before_action :push_abilities, only: [:index]

      feature_category :virtual_registry
      urgency :low

      def index; end

      private

      def ensure_feature!
        render_404 unless ::VirtualRegistries::Container.virtual_registry_available?(group, current_user)
      end

      def push_abilities
        push_frontend_ability(ability: :update_virtual_registry,
          resource: group.virtual_registry_policy_subject, user: current_user)
        push_frontend_ability(ability: :destroy_virtual_registry,
          resource: group.virtual_registry_policy_subject, user: current_user)
        push_frontend_ability(ability: :create_virtual_registry,
          resource: group.virtual_registry_policy_subject, user: current_user)
        push_frontend_ability(ability: :read_virtual_registry_cleanup_policy,
          resource: group.virtual_registry_policy_subject, user: current_user)
      end
    end
  end
end
