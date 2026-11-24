# frozen_string_literal: true

module AuditEvents
  module Instance
    class AmazonS3Configuration < ApplicationRecord
      include Limitable
      include ExternallyCommonDestinationable
      include AwsExternallyDestinationable
      include InstanceStreamDestinationMappable
      include Gitlab::EncryptedAttribute
      include Activatable

      self.limit_name = 'audit_events_amazon_s3_configurations'
      self.limit_scope = Limitable::GLOBAL_SCOPE
      self.table_name = 'audit_events_instance_amazon_s3_configurations'

      ACCESS_KEY_ID_REGEX = /\A\w+\z/
      AWS_BUCKET_NAME_REGEXP = /\A[a-z0-9][a-z0-9\-.]*\z/

      validates :name, presence: true, uniqueness: true
      validates :secret_access_key, presence: true
      validates :access_key_xid, presence: true,
        format: { with: ACCESS_KEY_ID_REGEX, message: 'must only contain letters, digits or underscore' },
        length: { in: 16..128 }
      validates :bucket_name, presence: true,
        format: { with: AWS_BUCKET_NAME_REGEXP },
        length: { maximum: 63 }, uniqueness: true

      attr_encrypted :secret_access_key,
        mode: :per_attribute_iv,
        key: :db_key_base_32,
        algorithm: 'aes-256-gcm',
        encode: false,
        encode_iv: false

      def allowed_to_stream?(*)
        true
      end
    end
  end
end
