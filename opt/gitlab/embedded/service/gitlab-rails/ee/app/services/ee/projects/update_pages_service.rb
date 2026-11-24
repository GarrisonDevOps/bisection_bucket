# frozen_string_literal: true

module EE
  module Projects
    module UpdatePagesService
      extend ::Gitlab::Utils::Override

      override :pages_deployment_attributes
      def pages_deployment_attributes(file, build)
        super.merge({
          path_prefix: path_prefix,
          expires_at: expires_at
        })
      end

      private

      def fallback_expiry_date
        value = ::Gitlab::CurrentSettings.pages_extra_deployments_default_expiry_seconds

        # A value of 0 means deployments should not expire, in this case return nil
        value.seconds.from_now if value.nonzero?
      end

      def custom_expire_in
        build.pages&.fetch(:expire_in, nil)
      end

      def custom_expiry_date
        ::Gitlab::Ci::Build::DurationParser.new(custom_expire_in).seconds_from_now
      end

      def expiry_customised?
        custom_expire_in.present?
      end

      # returns a datetime for the expiry or may return nil if expire_in='never'
      def expires_at
        return custom_expiry_date if expiry_customised?

        fallback_expiry_date if extra_deployment?
      end
    end
  end
end
