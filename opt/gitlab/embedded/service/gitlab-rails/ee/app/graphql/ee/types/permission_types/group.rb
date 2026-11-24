# frozen_string_literal: true

# rubocop:disable Gitlab/BoundedContexts -- the PermissionTypes::Group already exists in CE, this is just the EE extension
module EE
  module Types
    module PermissionTypes
      module Group
        extend ActiveSupport::Concern

        prepended do
          include ::Security::ScanProfilePermissions

          abilities :generate_description, :admin_work_item_lifecycle, :admin_ai_catalog_item_consumer

          ability_field :read_runner_cloud_provisioning_info,
            experiment: { milestone: '18.8' }

          ability_field :read_pro_ai_analytics,
            experiment: { milestone: '19.5' }

          ability_field :read_enterprise_ai_analytics,
            experiment: { milestone: '19.6' }

          ability_field :read_orbit_setting,
            experiment: { milestone: '19.4' }

          ability_field :read_orbit_trial,
            experiment: { milestone: '19.5' }

          ability_field :start_orbit_trial,
            experiment: { milestone: '19.5' }

          ability_field :update_knowledge_graph_setting,
            experiment: { milestone: '19.4' }

          ability_field :read_dora4_analytics,
            experiment: { milestone: '19.5' }

          ability_field :read_cycle_analytics,
            experiment: { milestone: '19.5' }

          ability_field :read_security_resource,
            experiment: { milestone: '19.5' }
        end
      end
    end
  end
end
# rubocop:enable Gitlab/BoundedContexts
