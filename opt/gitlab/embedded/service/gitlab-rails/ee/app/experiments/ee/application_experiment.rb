# frozen_string_literal: true

module EE
  module ApplicationExperiment
    extend ActiveSupport::Concern

    class_methods do
      extend ::Gitlab::Utils::Override

      override :available?
      def available?
        ::Gitlab::Saas.feature_available?(:experimentation)
      end
    end
  end
end
