# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module Welcome
      class ResubmitComponent < Trials::ResubmitComponent
        extend ::Gitlab::Utils::Override

        private

        override :submit_method
        def submit_method
          :put
        end

        override :extra_top_classes
        def extra_top_classes
          %w[gl-p-8 gl-bg-subtle gl-rounded-t-lg gl-border]
        end

        override :top_page_component
        def top_page_component
          GitlabSubscriptions::Trials::Ultimate::TopPageComponent
        end
      end
    end
  end
end
