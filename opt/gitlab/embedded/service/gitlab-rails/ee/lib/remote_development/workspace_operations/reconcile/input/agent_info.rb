# frozen_string_literal: true

module RemoteDevelopment
  module WorkspaceOperations
    module Reconcile
      module Input
        class AgentInfo
          attr_reader :name, :namespace, :actual_state, :deployment_resource_version

          # @param [String] name
          # @param [String] namespace
          # @param [String] actual_state
          # @param [String] deployment_resource_version
          # @return [RemoteDevelopment::WorkspaceOperations::Reconcile::Input::AgentInfo]
          def initialize(name:, namespace:, actual_state:, deployment_resource_version:)
            @name = name
            @namespace = namespace
            @actual_state = actual_state
            @deployment_resource_version = deployment_resource_version
          end

          # @param [RemoteDevelopment::WorkspaceOperations::Input::AgentInfo] other
          # @return [TrueClass, FalseClass]
          def ==(other)
            return false unless other && self.class == other.class

            other.name == name &&
              other.namespace == namespace &&
              other.actual_state == actual_state &&
              other.deployment_resource_version == deployment_resource_version
          end
        end
      end
    end
  end
end
