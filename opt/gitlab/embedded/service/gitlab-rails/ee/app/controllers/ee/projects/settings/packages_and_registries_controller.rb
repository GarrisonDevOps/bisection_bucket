# frozen_string_literal: true

module EE
  module Projects
    module Settings
      module PackagesAndRegistriesController
        extend ActiveSupport::Concern

        prepended do
          before_action only: :show do
            push_frontend_ability(
              ability: :create_container_registry_protection_immutable_tag_rule,
              resource: project,
              user: current_user
            )
          end
        end
      end
    end
  end
end
