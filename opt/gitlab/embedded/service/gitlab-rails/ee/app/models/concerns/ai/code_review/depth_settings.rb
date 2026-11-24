# frozen_string_literal: true

module Ai
  module CodeReview
    module DepthSettings
      extend ActiveSupport::Concern

      included do
        # Declared so that models load before the column exists, for example while migrating.
        attribute :duo_code_review_default_depth, :integer, limit: 2

        enum :duo_code_review_default_depth, ::Gitlab::Duo::CodeReview::DEPTH_VALUES,
          prefix: true, scopes: false, instance_methods: false,
          validate: { allow_nil: true, if: :will_save_change_to_duo_code_review_default_depth? }

        before_validation :reset_duo_code_review_default_depth, if: :duo_code_review_depth_settings_changing?

        if respond_to?(:cascading_attr, true)
          # NamespaceSetting and ProjectSetting cascade like any other cascading attribute.
          cascading_attr :duo_code_review_depth_allowed, :duo_code_review_default_depth
        else
          # ApplicationSetting is the root of the cascade and has no cascading_attr and always needs a default depth.
          validates :duo_code_review_default_depth, presence: true

          # Mirror the column defaults so the model saves before the columns exist, for example in migration specs.
          attribute :duo_code_review_depth_allowed, default: true
          attribute :duo_code_review_default_depth, default: ::Gitlab::Duo::CodeReview::LITE_DEPTH
        end
      end

      private

      # Standard requires Standard reviews to be allowed. The values are the cascaded ones,
      # so an inherited Standard is reset too.
      def reset_duo_code_review_default_depth
        return if duo_code_review_depth_allowed
        return unless duo_code_review_default_depth == ::Gitlab::Duo::CodeReview::STANDARD_DEPTH

        self.duo_code_review_default_depth = ::Gitlab::Duo::CodeReview::LITE_DEPTH
      end

      def duo_code_review_depth_settings_changing?
        will_save_change_to_duo_code_review_default_depth? || will_save_change_to_duo_code_review_depth_allowed?
      end
    end
  end
end
