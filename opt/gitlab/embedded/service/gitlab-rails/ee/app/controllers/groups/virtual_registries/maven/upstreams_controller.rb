# frozen_string_literal: true

module Groups
  module VirtualRegistries
    module Maven
      class UpstreamsController < Groups::VirtualRegistries::BaseController
        before_action :verify_read_virtual_registry!, only: [:show]
        before_action :verify_update_virtual_registry!, only: [:edit]
        before_action :set_upstream, only: [:edit, :show]
        before_action :push_ability, only: [:edit, :show]
        before_action :push_update_ability, only: [:show]

        feature_category :virtual_registry
        urgency :low

        def edit; end

        def show; end

        private

        def set_upstream
          @maven_upstream = ::VirtualRegistries::Packages::Maven::Upstream
            .find_by_id_and_group_id!(find_params[:id], group.id)
        end

        def find_params
          params.permit(:id)
        end

        def push_ability
          push_frontend_ability(ability: :destroy_virtual_registry,
            resource: group.virtual_registry_policy_subject, user: current_user)
        end

        def push_update_ability
          push_frontend_ability(ability: :update_virtual_registry,
            resource: group.virtual_registry_policy_subject, user: current_user)
        end
      end
    end
  end
end
