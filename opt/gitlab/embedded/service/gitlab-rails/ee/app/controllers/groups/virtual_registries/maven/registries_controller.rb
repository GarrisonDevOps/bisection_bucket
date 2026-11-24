# frozen_string_literal: true

module Groups
  module VirtualRegistries
    module Maven
      class RegistriesController < Groups::VirtualRegistries::BaseController
        before_action :verify_read_virtual_registry!, only: [:show]
        before_action :verify_create_virtual_registry!, only: [:new, :create]
        before_action :verify_update_virtual_registry!, only: [:edit, :update]
        before_action :verify_destroy_virtual_registry!, only: [:destroy]
        before_action :set_registry, only: [:show, :edit, :update, :destroy]

        before_action :push_abilities, only: [:show]

        feature_category :virtual_registry
        urgency :low

        def new
          @maven_registry = ::VirtualRegistries::Packages::Maven::Registry.new
        end

        def create
          @maven_registry = ::VirtualRegistries::Packages::Maven::Registry.new(
            action_params.merge(group:)
          )

          if @maven_registry.save
            redirect_to group_virtual_registries_maven_registry_path(group, @maven_registry),
              notice: s_("VirtualRegistry|Maven virtual registry was created")
          else
            render :new
          end
        end

        def show; end

        def edit; end

        def update
          if @maven_registry.update(action_params)
            redirect_to group_virtual_registries_maven_registry_path(group, @maven_registry),
              notice: s_("VirtualRegistry|Maven virtual registry was updated")
          else
            render :edit
          end
        end

        def destroy
          if @maven_registry.destroy
            flash[:notice] = s_('VirtualRegistry|Maven virtual registry was deleted')
            redirect_to group_virtual_registries_maven_registries_and_upstreams_path(group)
          else
            flash[:alert] = @maven_registry.errors.full_messages.to_sentence
            render :edit
          end
        end

        private

        def push_abilities
          push_frontend_ability(ability: :update_virtual_registry,
            resource: group.virtual_registry_policy_subject, user: current_user)
          push_frontend_ability(ability: :create_virtual_registry,
            resource: group.virtual_registry_policy_subject, user: current_user)
          push_frontend_ability(ability: :destroy_virtual_registry,
            resource: group.virtual_registry_policy_subject, user: current_user)
        end

        def set_registry
          @maven_registry = ::VirtualRegistries::Packages::Maven::Registry
            .find_by_id_and_group_id!(registry_params[:id], group.id)
        end

        def registry_params
          params.permit(:id)
        end

        def action_params
          params.require(:maven_registry).permit(:name, :description)
        end
      end
    end
  end
end
