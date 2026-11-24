# frozen_string_literal: true

module GitlabSubscriptions
  module Subscriptions
    module Welcome
      class ResubmitComponent < ViewComponent::Base
        def initialize(**kwargs)
          @hidden_fields = kwargs[:hidden_fields]
          @submit_path = kwargs[:submit_path]
        end

        private

        attr_reader :hidden_fields, :submit_path

        delegate :page_title, to: :helpers

        def submit_method
          :put
        end

        def extra_top_classes
          %w[gl-p-8 gl-bg-subtle gl-rounded-t-lg gl-border]
        end

        def before_render
          content_for :body_class, '!gl-bg-default'
        end

        def resubmit_button_data
          {}
        end
      end
    end
  end
end
