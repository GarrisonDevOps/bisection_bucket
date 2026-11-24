# frozen_string_literal: true

module GitlabSubscriptions
  module Trials
    module DuoPro
      def self.show_duo_usage_settings?(namespace)
        add_on_purchase = GitlabSubscriptions::DuoPro.any_add_on_purchase_for_namespace(namespace)
        return false unless add_on_purchase.present?

        if add_on_purchase.trial?
          GitlabSubscriptions::Trials::AddOnStatus.new(add_on_purchase: add_on_purchase).show?
        else
          add_on_purchase.active?
        end
      end
    end
  end
end
