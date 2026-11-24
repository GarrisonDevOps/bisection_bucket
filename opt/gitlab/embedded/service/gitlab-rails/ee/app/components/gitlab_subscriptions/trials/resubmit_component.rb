# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class ResubmitComponent < ViewComponent::Base
      def initialize(**kwargs)
        @hidden_fields = kwargs[:hidden_fields]
        @submit_path = kwargs[:submit_path]
      end

      private

      attr_reader :hidden_fields, :submit_path

      def submit_method
        :post
      end

      def extra_top_classes
        []
      end

      def before_render
        content_for :body_class, '!gl-bg-default'
      end

      def top_page_component
        raise NoMethodError, 'This method must be implemented in a subclass'
      end

      def resubmit_button_data
        {}
      end
    end
  end
end
