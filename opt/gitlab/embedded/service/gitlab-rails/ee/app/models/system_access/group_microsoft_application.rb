# frozen_string_literal: true

module SystemAccess # rubocop:disable Gitlab/BoundedContexts -- Spliting existing table
  class GroupMicrosoftApplication < ApplicationRecord
    include Gitlab::EncryptedAttribute

    ignore_column :temp_source_id, remove_with: '18.8', remove_after: '2025-12-22'

    belongs_to :group
    has_one :graph_access_token,
      class_name: '::SystemAccess::GroupMicrosoftGraphAccessToken',
      inverse_of: :system_access_group_microsoft_application,
      foreign_key: :system_access_group_microsoft_application_id

    # legacy method to provide compatibility with SystemAccess::MicrosoftApplication
    has_one :system_access_microsoft_graph_access_token,
      class_name: '::SystemAccess::GroupMicrosoftGraphAccessToken',
      inverse_of: :system_access_group_microsoft_application,
      foreign_key: :system_access_group_microsoft_application_id

    validates :enabled, inclusion: { in: [true, false] }
    validates :group_id, uniqueness: true
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

    # for compatibility with SystemAccess::MicrosoftApplication
    # called in Microsoft::GraphClient
    def build_system_access_microsoft_graph_access_token(attrs = {})
      super(attrs.reverse_merge(group: group))
    end
  end
end
