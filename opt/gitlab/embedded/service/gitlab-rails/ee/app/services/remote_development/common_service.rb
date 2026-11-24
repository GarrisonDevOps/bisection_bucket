# frozen_string_literal: true

require_relative '../../../../lib/gitlab/fp/rop_helpers'

module RemoteDevelopment
  class CommonService
    extend Gitlab::Fp::RopHelpers
    extend ServiceResponseFactory
    include Gitlab::InternalEvents

    # NOTE: This service intentionally does not follow the conventions for object-based service classes as documented in
    #       https://docs.gitlab.com/ee/development/reusing_abstractions.html#service-classes.
    #
    #       See "Minimal service layer" at
    #       https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/lib/remote_development/README.md#minimal-service-layer
    #       for more details on this decision.
    #
    #       See "Service layer code example" at
    #       https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/lib/remote_development/README.md#service-layer-code-example
    #       for an explanatory code example of invoking and using this class.

    # @param [Class] domain_main_class
    # @param [Hash] domain_main_class_args
    # @return [ServiceResponse]
    def self.execute(domain_main_class:, domain_main_class_args:)
      raise 'domain_main_class_args must be a Hash' unless domain_main_class_args.is_a?(Hash)

      main_class_method = retrieve_single_public_singleton_method(domain_main_class)

      settings = RemoteDevelopment::Settings.get(RemoteDevelopment::Settings::DefaultSettings.default_settings.keys)
      logger = RemoteDevelopment::Logger.build
      internal_events_class = Gitlab::InternalEvents

      response_hash = domain_main_class.singleton_method(main_class_method).call(
        **domain_main_class_args.merge(settings: settings, logger: logger, internal_events_class: internal_events_class)
      )

      create_service_response(response_hash)
    end
  end
end
