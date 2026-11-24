# frozen_string_literal: true

module Authn
  module IamService
    # An OAuth application as IAM describes it, for consents whose application
    # was registered on another cell and has no row in oauth_applications.
    RemoteOauthApplication = Struct.new(
      :client_id, :name, :owner_label, :created_at, :dynamic, :placeholder, keyword_init: true
    ) do
      def self.from_managed_client(client)
        new(
          client_id: client.client_id,
          name: client.client_name.presence || client.client_id,
          owner_label: client.owner.presence,
          created_at: client.created_at && Time.zone.at(client.created_at.seconds),
          dynamic: client.dynamic
        )
      end

      # Stands in for an application IAM could not describe in time.
      def self.placeholder(client_id)
        new(client_id: client_id, name: client_id, placeholder: true)
      end

      def dynamic?
        dynamic == true
      end

      def placeholder?
        placeholder == true
      end
    end
  end
end
