# frozen_string_literal: true

module DependencyProxy
  module Packages
    class Setting < ApplicationRecord
      include Gitlab::EncryptedAttribute

      self.primary_key = :project_id

      belongs_to :project, inverse_of: :dependency_proxy_packages_setting

      attr_encrypted :maven_external_registry_username,
        mode: :per_attribute_iv,
        key: :db_key_base_32,
        algorithm: 'aes-256-gcm',
        encode: false,
        encode_iv: false
      attr_encrypted :maven_external_registry_password,
        mode: :per_attribute_iv,
        key: :db_key_base_32,
        algorithm: 'aes-256-gcm',
        encode: false,
        encode_iv: false
      attr_encrypted :npm_external_registry_basic_auth,
        mode: :per_attribute_iv,
        key: :db_key_base_32,
        algorithm: 'aes-256-gcm',
        encode: false,
        encode_iv: false
      attr_encrypted :npm_external_registry_auth_token,
        mode: :per_attribute_iv,
        key: :db_key_base_32,
        algorithm: 'aes-256-gcm',
        encode: false,
        encode_iv: false

      before_validation :nullify_credentials_values

      validates :project, presence: true

      validates_with AnyFieldValidator, fields: %w[maven_external_registry_url npm_external_registry_url]

      # maven
      validates :maven_external_registry_url,
        addressable_url: { allow_localhost: false, allow_local_network: false },
        if: :maven_external_registry_url?
      validates :maven_external_registry_username, presence: true, if: :maven_external_registry_password?
      validates :maven_external_registry_password, presence: true, if: :maven_external_registry_username?
      validates :maven_external_registry_url,
        :maven_external_registry_username,
        :maven_external_registry_password,
        length: { maximum: 255 }

      # npm
      validate :validate_npm_external_registry_tokens
      validates :npm_external_registry_url,
        addressable_url: { allow_localhost: false, allow_local_network: false },
        if: :npm_external_registry_url?
      validates :npm_external_registry_url,
        :npm_external_registry_basic_auth,
        :npm_external_registry_auth_token,
        length: { maximum: 255 }

      after_validation :reset_maven_credentials, if: -> { persisted? && maven_external_registry_url_changed? }

      scope :enabled, -> { where(enabled: true) }

      def url_from_maven_upstream(path:, file_name:)
        full_url = [maven_external_registry_url, path, file_name].join('/')
        uri = Addressable::URI.parse(full_url)
        uri.path = uri.path.squeeze('/')

        uri.to_s
      end

      def headers_from_maven_upstream
        return {} unless maven_external_registry_username.present? && maven_external_registry_password.present?

        authorization = ActionController::HttpAuthentication::Basic.encode_credentials(
          maven_external_registry_username,
          maven_external_registry_password
        )

        { Authorization: authorization }
      end

      private

      def nullify_credentials_values
        self.maven_external_registry_username = nil if maven_external_registry_username.blank?
        self.maven_external_registry_password = nil if maven_external_registry_password.blank?
        self.npm_external_registry_basic_auth = nil if npm_external_registry_basic_auth.blank?
        self.npm_external_registry_auth_token = nil if npm_external_registry_auth_token.blank?
      end

      def validate_npm_external_registry_tokens
        return unless npm_external_registry_basic_auth.present? && npm_external_registry_auth_token.present?

        errors.add(:base, "Npm external registry basic auth and auth token can't be set at the same time")
      end

      def reset_maven_credentials
        return if maven_external_registry_username_changed? && maven_external_registry_password_changed?

        self.maven_external_registry_username = nil
        self.maven_external_registry_password = nil
        self.encrypted_maven_external_registry_username_iv = nil
        self.encrypted_maven_external_registry_password_iv = nil
      end
    end
  end
end
