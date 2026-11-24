# frozen_string_literal: true

module Groups
  module VirtualRegistries
    module Maven
      class RegistriesAndUpstreamsController < Groups::VirtualRegistries::BaseController
        before_action :verify_read_virtual_registry!, only: [:index]

        before_action :push_abilities, only: [:index]

        feature_category :virtual_registry
        urgency :low

        def index; end

        private

        def push_abilities
          push_frontend_ability(ability: :update_virtual_registry,
            resource: group.virtual_registry_policy_subject, user: current_user)
          push_frontend_ability(ability: :read_virtual_registry_cleanup_policy,
            resource: group.virtual_registry_policy_subject, user: current_user)
        end
      end
    end
  end
end
