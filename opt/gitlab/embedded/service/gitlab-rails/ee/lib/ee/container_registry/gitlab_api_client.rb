# frozen_string_literal: true

module EE
  module ContainerRegistry
    module GitlabApiClient
      extend ::Gitlab::Utils::Override

      override :patch_repository
      def patch_repository(path, body, dry_run: false)
        return :bad_request if ::Gitlab::Geo.enabled?

        super
      end
    end
  end
end
