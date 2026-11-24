# frozen_string_literal: true

module Ci
  module Minutes
    class UsagePresenter < Gitlab::View::Presenter::Simple
      include Gitlab::Utils::StrongMemoize

      presents Usage, as: :usage

      Label = Struct.new(:text, :css_class)

      # Status of the monthly allowance being used.
      def monthly_minutes_label
        text = "#{monthly_minutes_used} / #{monthly_minutes_limit_text}"
        css_class = monthly_minutes_label_css_class

        Label.new(text, css_class)
      end

      def monthly_minutes_used
        usage.monthly_minutes_used
      end

      def monthly_minutes_limit_text
        return _('Not supported') unless display_shared_runners_data?
        return _('Unlimited') unless display_minutes_available_data?

        usage.quota.monthly
      end

      def monthly_percent_used
        return 0 unless usage.quota_enabled?
        return 0 if usage.quota.monthly == 0

        100 * usage.monthly_minutes_used.to_i / usage.quota.monthly
      end

      # Status of any purchased minutes used.
      def purchased_minutes_label
        text = "#{purchased_minutes_used} / #{purchased_minutes_limit}"
        css_class = purchased_minutes_label_css_class

        Label.new(text, css_class)
      end

      def purchased_minutes_used
        usage.purchased_minutes_used
      end

      def purchased_minutes_limit
        usage.quota.purchased
      end

      def purchased_percent_used
        return 0 unless usage.quota_enabled?
        return 0 unless usage.quota.any_purchased?

        100 * usage.purchased_minutes_used.to_i / usage.quota.purchased
      end

      def display_minutes_available_data?
        display_shared_runners_data? && usage.quota_enabled?
      end

      def display_shared_runners_data?
        usage.namespace.root? && any_project_enabled?
      end

      def any_project_enabled?
        strong_memoize(:any_project_enabled) do
          usage.namespace.any_project_with_shared_runners_enabled?
        end
      end

      private

      def monthly_minutes_label_css_class
        return '' unless usage.quota_enabled?

        usage.monthly_minutes_used_up? ? 'gl-text-danger' : 'gl-text-success'
      end

      def purchased_minutes_label_css_class
        usage.purchased_minutes_used_up? ? 'gl-text-danger' : 'gl-text-success'
      end
    end
  end
end
