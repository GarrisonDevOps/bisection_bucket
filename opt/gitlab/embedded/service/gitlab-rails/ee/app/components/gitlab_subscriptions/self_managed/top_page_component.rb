# frozen_string_literal: true

module GitlabSubscriptions
  module SelfManaged
    class TopPageComponent < Trials::TopPageComponent
      extend ::Gitlab::Utils::Override

      private

      override :title
      def title
        s_('Trial|Start your free Ultimate trial')
      end
    end
  end
end
