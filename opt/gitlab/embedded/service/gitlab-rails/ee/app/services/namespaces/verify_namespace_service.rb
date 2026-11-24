# frozen_string_literal: true

module Namespaces
  class VerifyNamespaceService
    def initialize(namespace, verification_level)
      @namespace = namespace
      @verification_level = verification_level
      @errors = []
    end

    def execute
      verify_namespace_is_a_root
      verify_verification_level

      return ServiceResponse.error(message: errors.join(', ')) if errors.any?

      create_or_update_verified_namespace
      update_catalog_resources

      ServiceResponse.success
    end

    private

    attr_reader :namespace, :verification_level, :errors

    def verify_namespace_is_a_root
      return if namespace.root?

      errors << 'Input the root namespace.'
    end

    def verify_verification_level
      levels = ::Namespaces::VerifiedNamespace::VERIFICATION_LEVELS

      return if levels.key?(verification_level.to_sym)

      allowed_levels = if ::Gitlab::Saas.feature_available?(:gitlab_com_subscriptions)
                         levels.excluding(:verified_creator_self_managed).keys.join(', ')
                       else
                         'verified_creator_self_managed'
                       end

      errors << "Input a valid verification level: #{allowed_levels}."
    end

    def create_or_update_verified_namespace
      verified_namespace = ::Namespaces::VerifiedNamespace.find_or_create_by_namespace!(namespace)

      return if verified_namespace.verification_level == verification_level

      verified_namespace.update!(verification_level: verification_level)
    end

    def update_catalog_resources
      namespace.all_catalog_resources.update_all(verification_level: verification_level)
    end
  end
end
