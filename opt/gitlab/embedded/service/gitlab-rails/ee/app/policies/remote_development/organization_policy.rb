# frozen_string_literal: true

module RemoteDevelopment
  module OrganizationPolicy
    extend ActiveSupport::Concern

    included do
      rule { can?(:update_organization) }.policy do
        enable :read_organization_cluster_agent_mapping
      end

      rule { organization_user }.enable :read_organization_cluster_agent_mapping
    end
  end
end
