# frozen_string_literal: true

module SystemAccess
  class MicrosoftGraphAccessToken < ApplicationRecord
    include Gitlab::EncryptedAttribute

    belongs_to :system_access_microsoft_application,
      class_name: 'SystemAccess::MicrosoftApplication',
      inverse_of: :system_access_microsoft_graph_access_token

    validates :system_access_microsoft_application_id, presence: true, uniqueness: true
    validates :expires_in, presence: true, numericality: { greater_than_or_equal_to: 0 }

    attr_encrypted :token,
      key: :db_key_base_32,
      mode: :per_attribute_iv,
      algorithm: 'aes-256-gcm'

    def expired?
      return true unless persisted?

      updated_at.utc + expires_in < DateTime.now.utc
    end
  end
end
