# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    class TopPageComponent < ViewComponent::Base
      delegate :page_title, to: :helpers

      private

      def title
        raise NoMethodError, 'This method must be implemented in a subclass'
      end
    end
  end
end
