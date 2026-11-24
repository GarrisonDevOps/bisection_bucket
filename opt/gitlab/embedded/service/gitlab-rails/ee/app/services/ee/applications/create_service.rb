# frozen_string_literal: true

module EE
  module Applications
    module CreateService
      extend ::Gitlab::Utils::Override

      override :execute
      def execute
        super.tap do |application|
          # NOTE: When this service is invoked from an internal API (such as KAS) or a background job,
          #       the request object may be nil or lack an IP address. We gracefully pass nil
          #       for the IP address in these cases, as Gitlab::Audit::Auditor automatically
          #       falls back to Gitlab::RequestContext.instance.client_ip.
          #       Additionally, Grape API requests respond to `ip` rather than `remote_ip`.
          #
          #       However, we must still exit early if `application.owner` and `current_user`
          #       are missing, because the audit framework requires a valid scope/entity.

          remote_ip = request.try(:remote_ip) || request.try(:ip) if request.present?

          entity = application.owner || current_user

          next unless application.persisted? && entity

          audit_oauth_application_creation(application, remote_ip, entity)
        end
      end

      private

      def audit_oauth_application_creation(application, ip_address, entity)
        ::Gitlab::Audit::Auditor.audit(
          name: 'oauth_application_created',
          author: current_user,
          scope: entity,
          target: application,
          message: 'OAuth application added',
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
