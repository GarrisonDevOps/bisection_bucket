# frozen_string_literal: true

module EE
  module Types
    module PermissionTypes
      module Project
        extend ActiveSupport::Concern

        prepended do
          abilities :read_path_locks, :create_path_lock, :admin_path_locks, :generate_description,
            :admin_work_item_lifecycle

          ability_field :manage_ai_flow_triggers,
            experiment: { milestone: '18.3' }

          ability_field :read_ai_catalog_item,
            experiment: { milestone: '18.3' }

          ability_field :read_ai_catalog_item_consumer,
            experiment: { milestone: '18.3' }

          ability_field :admin_ai_catalog_item,
            experiment: { milestone: '18.3' }

          ability_field :admin_ai_catalog_item_consumer,
            experiment: { milestone: '18.3' }

          ability_field :create_ai_catalog_item_consumer,
            experiment: { milestone: '19.3' },
            description: 'If `true`, the user can enable an AI catalog item in this project by ' \
              'creating an item consumer.'

          ability_field :read_runner_cloud_provisioning_info,
            experiment: { milestone: '18.8' }

          ability_field :read_project_component_usages,
            experiment: { milestone: '19.0' }

          ability_field :read_pro_ai_analytics,
            experiment: { milestone: '19.5' }

          ability_field :read_dora4_analytics,
            experiment: { milestone: '19.5' }

          ability_field :read_security_resource,
            experiment: { milestone: '19.5' }
        end
      end
    end
  end
end
