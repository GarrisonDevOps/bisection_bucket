# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module Ultimate
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
end
