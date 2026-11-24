# frozen_string_literal: true

module Gitlab
  module Ci
    class Config
      module Entry
        module Akeyless
          class Secret < ::Gitlab::Config::Entry::Node
            include ::Gitlab::Config::Entry::Validatable
            include ::Gitlab::Config::Entry::Attributable

            ALLOWED_KEYS = %i[name data_key cert_user_name public_key_data csr_data
              uid_token gcp_audience azure_object_id
              k8s_service_account_token k8s_auth_config_name
              gateway_ca_certificate].freeze
            attributes ALLOWED_KEYS

            validations do
              validates :config, type: Hash, allowed_keys: ALLOWED_KEYS
              validates :name, type: String, allow_nil: true
              validates :data_key, type: String, allow_nil: true
              validates :cert_user_name, type: String, allow_nil: true
              validates :public_key_data, type: String, allow_nil: true
              validates :csr_data, type: String, allow_nil: true
              validates :uid_token, type: String, allow_nil: true
              validates :gcp_audience, type: String, allow_nil: true
              validates :azure_object_id, type: String, allow_nil: true
              validates :k8s_service_account_token, type: String, allow_nil: true
              validates :k8s_auth_config_name, type: String, allow_nil: true
              validates :gateway_ca_certificate, type: String, allow_nil: true
            end

            def value
              {
                name: name,
                data_key: data_key,
                cert_user_name: cert_user_name,
                public_key_data: public_key_data,
                csr_data: csr_data,
                uid_token: uid_token,
                gcp_audience: gcp_audience,
                azure_object_id: azure_object_id,
                k8s_service_account_token: k8s_service_account_token,
                k8s_auth_config_name: k8s_auth_config_name,
                gateway_ca_certificate: gateway_ca_certificate
              }
            end
          end
        end
      end
    end
  end
end
