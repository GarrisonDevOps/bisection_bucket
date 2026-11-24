# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      module Saml
        module SsoSessionFilterable
          extend ActiveSupport::Concern

          private

          def filter_by_saml_sso_session(collection, filter_param)
            return collection unless params.fetch(filter_param, false)
            return collection if current_user.nil? || current_user.can_read_all_resources?

            saml_providers_to_exclude = current_user.expired_sso_session_saml_providers_with_access_restricted

            return collection if saml_providers_to_exclude.blank?

            collection.by_not_in_root_id(
              saml_providers_to_exclude.map(&:group_id)
            )
          end
        end
      end
    end
  end
end
