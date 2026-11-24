# frozen_string_literal: true

module API
  module Concerns
    module VirtualRegistries
      module Container
        module SharedSetup
          extend ActiveSupport::Concern

          included do
            feature_category :virtual_registry
            urgency :low

            after_validation do
              unauthorized! unless ::Feature.enabled?(:container_virtual_registries, target_group)
              not_found! unless ::Gitlab.config.dependency_proxy.enabled
              not_found! unless target_group.licensed_feature_available?(:container_virtual_registry)
              not_found! unless ::VirtualRegistries::Setting.find_for_group(target_group).enabled

              authenticate!

              # return not found response to authenticated users but non member of target group
              policy_subject = target_group.virtual_registry_policy_subject
              not_found! unless Ability.allowed?(current_user, :read_virtual_registry, policy_subject)
            end
          end
        end
      end
    end
  end
end
