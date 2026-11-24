# frozen_string_literal: true

module DependencyManagement
  module SecurityUpdate
    module BatchUpdates
      def self.enabled?(project:, configuration:)
        Feature.enabled?(:dependency_management_batch_updates, project) && configuration[:batch_updates] == true
      end
    end
  end
end
