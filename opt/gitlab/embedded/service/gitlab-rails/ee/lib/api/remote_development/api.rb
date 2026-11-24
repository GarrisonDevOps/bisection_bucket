# frozen_string_literal: true

module API
  module RemoteDevelopment
    class API < ::API::Base
      mount ::API::RemoteDevelopment::Internal::Agents::Agentw::AgentInfo
      mount ::API::RemoteDevelopment::Internal::Agents::Agentw::AuthorizeUserAccess
      mount ::API::RemoteDevelopment::Internal::Agents::Agentw::ServerConfig
    end
  end
end
