# frozen_string_literal: true

module Groups
  class VirtualRegistriesController < Groups::ApplicationController
    before_action :ensure_feature!
    before_action :push_abilities, only: [:index]

    feature_category :virtual_registry
    urgency :low

    def index; end

    private

    def ensure_feature!
      render_404 unless feature_available?
    end

    def feature_available?
      ::VirtualRegistries.any_registry_available?(group, current_user)
    end

    def push_abilities
      push_frontend_ability(ability: :create_virtual_registry,
        resource: group.virtual_registry_policy_subject, user: current_user)
    end
  end
end
