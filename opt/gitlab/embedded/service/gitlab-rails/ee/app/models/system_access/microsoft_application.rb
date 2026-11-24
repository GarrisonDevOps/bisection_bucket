# frozen_string_literal: true

module SystemAccess
  class MicrosoftApplication < ApplicationRecord
    include Gitlab::EncryptedAttribute

    belongs_to :namespace, optional: true
    has_one :system_access_microsoft_graph_access_token,
      class_name: '::SystemAccess::MicrosoftGraphAccessToken',
      inverse_of: :system_access_microsoft_application,
      foreign_key: :system_access_microsoft_application_id

    validates :enabled, inclusion: { in: [true, false] }
    validates :namespace_id, uniqueness: true
    validates :tenant_xid, presence: true
    validates :client_xid, presence: true
    validates :encrypted_client_secret, presence: true
    validates :client_secret, length: { maximum: 255 }, if: :client_secret_changed?
    validates :login_endpoint,
      presence: true,
      public_url: { schemes: %w[https], enforce_sanitization: true, ascii_only: true }
    validates :graph_endpoint,
      presence: true,
      public_url: { schemes: %w[https], enforce_sanitization: true, ascii_only: true }

    attr_encrypted :client_secret,
      key: :db_key_base_32,
      mode: :per_attribute_iv,
      algorithm: 'aes-256-gcm'

    def self.instance_application
      find_by(namespace_id: nil)
    end
  end
end
