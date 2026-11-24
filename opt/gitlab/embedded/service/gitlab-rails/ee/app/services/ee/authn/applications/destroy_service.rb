# frozen_string_literal: true

module EE
  module Authn
    module Applications
      module DestroyService
        extend ::Gitlab::Utils::Override

        override :execute
        def execute
          super.tap do |application|
            next unless application.destroyed?

            # Grape API requests respond to `ip` rather than `remote_ip`, so we fallback
            # to support both API and standard web requests.
            remote_ip = request.try(:remote_ip) || request.try(:ip) if request.present?

            entity = application.owner || current_user

            next unless entity

            audit_oauth_application_destruction(application, remote_ip, entity)
          end
        end

        private

        def audit_oauth_application_destruction(application, ip_address, entity)
          ::Gitlab::Audit::Auditor.audit(
            name: 'oauth_application_deleted',
            author: current_user,
            scope: entity,
            target: application,
            message: 'OAuth application deleted',
            additional_details: {
              application_name: application.name,
              application_id: application.id,
              scopes: application.scopes.to_a,
              redirect_uri: application.redirect_uri.to_s[0, 100]
            },
            ip_address: ip_address
          )
        end
      end
    end
  end
end
