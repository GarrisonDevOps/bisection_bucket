# frozen_string_literal: true

module API
  module Helpers
    module ScimHelpers
      def scim_not_found!(message:)
        render_scim_error(::API::Entities::Scim::NotFound, message)
      end

      def scim_error!(message:)
        render_scim_error(::API::Entities::Scim::Error, message)
      end

      def scim_conflict!(message:)
        render_scim_error(::API::Entities::Scim::Conflict, message)
      end

      def scim_bad_request!(message:, scim_type: nil)
        render_scim_error(::API::Entities::Scim::BadRequest, message, scim_type: scim_type)
      end

      def scim_forbidden!(message:)
        render_scim_error(::API::Entities::Scim::Forbidden, message)
      end

      def render_scim_error(error_class, message, scim_type: nil)
        error!({ with: error_class, detail: message, scim_type: scim_type }.compact, error_class::STATUS)
      end

      def sanitize_request_parameters(parameters)
        filter = ActiveSupport::ParameterFilter.new(::Rails.application.config.filter_parameters)
        filter.filter(parameters)
      end

      def update_scim_user(identity)
        parser = ::Gitlab::Scim::ParamsParser.new(params)
        parsed_hash = parser.update_params

        if parser.deprovision_user?
          patch_deprovision(identity)
        elsif parser.reprovision_user?
          reprovision(identity)
        elsif parsed_hash[:extern_uid]
          update_extern_uid(identity, parsed_hash[:extern_uid])
        else
          # With 15.0, we no longer allow modifying user attributes.
          # However, we mark the operation as successful to avoid breaking
          # existing automations
          :success
        end
      end
    end
  end
end
