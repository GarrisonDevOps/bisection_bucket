# frozen_string_literal: true

module Clusters
  module Agents
    class UrlConfiguration < ApplicationRecord
      include NullifyIfBlank
      include Gitlab::EncryptedAttribute

      self.table_name = 'cluster_agent_url_configurations'

      PUBLIC_KEY_MAX_LENGTH = 1024.bytes
      PRIVATE_KEY_MAX_LENGTH = 1024.bytes

      belongs_to :agent, class_name: 'Clusters::Agent', optional: false
      belongs_to :project, class_name: '::Project', optional: false
      belongs_to :created_by_user, class_name: 'User', optional: true

      validates :url, url: { schemes: %w[grpc grpcs] }

      validates :ca_cert, certificate: true, allow_blank: true
      validates :tls_host, host: true, allow_blank: true

      with_options if: :certificate_auth? do
        validates :client_cert, certificate: true
        validates :client_key, certificate_key: true

        validates :private_key, absence: true
      end

      with_options if: :public_key_auth? do
        validates :private_key, presence: true

        validates :client_cert, :client_key, absence: true
      end

      nullify_if_blank :client_key, :client_cert, :ca_cert, :tls_host

      validates :public_key, bytesize: { maximum: -> { PUBLIC_KEY_MAX_LENGTH } }, if: :public_key_changed?
      validates :private_key, bytesize: { maximum: -> { PRIVATE_KEY_MAX_LENGTH } }, if: :private_key_changed?

      attr_encrypted :private_key,
        mode: :per_attribute_iv,
        key: :db_key_base_32,
        algorithm: 'aes-256-gcm',
        encode: false,
        encode_iv: false

      enum :status, {
        active: 0,
        revoked: 1
      }

      after_create :set_agent_receptive!
      after_destroy :unset_agent_receptive!

      private

      def public_key_auth?
        public_key.present?
      end

      def certificate_auth?
        !public_key_auth?
      end

      def set_agent_receptive!
        agent.update!(is_receptive: true)
      end

      def unset_agent_receptive!
        agent.update!(is_receptive: false)
      end
    end
  end
end
