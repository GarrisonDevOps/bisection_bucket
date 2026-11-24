# frozen_string_literal: true

module RemoteDevelopment
  module GroupPolicy
    extend ActiveSupport::Concern

    included do
      rule { can?(:admin_namespace) }.enable :admin_namespace_cluster_agent_mapping
    end
  end
end
