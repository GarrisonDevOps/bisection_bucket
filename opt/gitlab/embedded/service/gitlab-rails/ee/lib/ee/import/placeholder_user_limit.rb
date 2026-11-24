# frozen_string_literal: true

module EE
  module Import
    module PlaceholderUserLimit
      extend ::Gitlab::Utils::Override

      LIMIT_TIER_2 = :import_placeholder_user_limit_tier_2
      LIMIT_TIER_3 = :import_placeholder_user_limit_tier_3
      LIMIT_TIER_4 = :import_placeholder_user_limit_tier_4

      private

      override :limit_name
      def limit_name
        return super unless plan.paid?

        case seats
        when ..100 then ::Import::PlaceholderUserLimit::LIMIT_TIER_1
        when 101..500 then LIMIT_TIER_2
        when 501..1_000 then LIMIT_TIER_3
        else LIMIT_TIER_4
        end
      end

      def seats
        @seats ||= root_namespace.gitlab_subscription.seats
      end
    end
  end
end
