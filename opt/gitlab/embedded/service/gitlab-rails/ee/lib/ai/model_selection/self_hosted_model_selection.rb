# frozen_string_literal: true

module Ai
  module ModelSelection
    class SelfHostedModelSelection
      def initialize(feature_setting)
        @feature_setting = feature_setting
      end

      def default_model
        model.to_model_selection
      end

      def selectable_models
        [model.to_model_selection]
      end

      def pinned_model
        model.to_model_selection
      end

      def do_not_consider_user_selected_model?(_user_selected_model_identifier)
        true
      end

      def credit_gated?(_model_ref)
        false
      end

      def user_selected_model_credit_gated?(_model_ref)
        false
      end

      private

      attr_reader :feature_setting

      def model
        feature_setting.self_hosted_model
      end
    end
  end
end
