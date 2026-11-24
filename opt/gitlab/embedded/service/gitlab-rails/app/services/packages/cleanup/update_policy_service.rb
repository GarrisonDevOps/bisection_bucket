# frozen_string_literal: true

module Packages
  module Cleanup
    class UpdatePolicyService < BaseProjectService
      ALLOWED_ATTRIBUTES = %i[keep_n_duplicated_package_files].freeze

      def execute
        return ServiceResponse.error(message: 'Access denied') unless allowed?

        if policy.update(policy_params)
          ServiceResponse.success(payload: { packages_cleanup_policy: policy })
        else
          ServiceResponse.error(message: policy.errors.full_messages.to_sentence || 'Bad request')
        end
      end

      private

      def policy
        project.packages_cleanup_policy
      end
      strong_memoize_attr :policy

      def allowed?
        can?(current_user, :admin_package, project)
      end

      def policy_params
        params.slice(*allowed_attributes)
      end

      def allowed_attributes
        return ALLOWED_ATTRIBUTES unless Feature.enabled?(:packages_cleanup_delete_generic_not_downloaded, project)

        ALLOWED_ATTRIBUTES + %i[delete_generic_packages_not_downloaded_in_days]
      end
    end
  end
end
