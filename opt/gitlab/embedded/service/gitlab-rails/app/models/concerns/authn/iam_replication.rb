# frozen_string_literal: true

module Authn
  module IamReplication
    def self.enabled?
      Feature.enabled?(:iam_data_replication, :instance)
    end

    def self.replicator_for(entity_type)
      case entity_type
      when 'oauth_application' then ::Authn::IamReplication::OauthApplicationReplicator
      when 'oauth_access_token' then ::Authn::IamReplication::OauthAccessTokenReplicator
      else raise ArgumentError, "unknown entity_type: #{entity_type.inspect}"
      end
    end
  end
end
