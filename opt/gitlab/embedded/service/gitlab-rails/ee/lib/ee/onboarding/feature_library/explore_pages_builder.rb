# frozen_string_literal: true

module EE
  module Onboarding
    module FeatureLibrary
      module ExplorePagesBuilder
        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        PAGE_COPY = {
          premium: {
            title: N_('FeatureLibrary|Explore Premium features'),
            subtitle: N_('FeatureLibrary|Control merges and plan work across teams'),
            highlights_title: N_('FeatureLibrary|Premium highlights')
          },
          ultimate: {
            title: N_('FeatureLibrary|Explore Ultimate features'),
            subtitle: N_('FeatureLibrary|All of Premium, plus security, analytics, and more'),
            highlights_title: N_('FeatureLibrary|Ultimate highlights')
          }
        }.freeze

        CREDITS_TITLE = N_('FeatureLibrary|Powered by GitLab Credits')

        LABEL_TEXT = {
          'new' => {
            premium: N_('FeatureLibrary|New with Premium'),
            ultimate: N_('FeatureLibrary|New with Ultimate')
          },
          'enhanced' => {
            premium: N_('FeatureLibrary|Enhanced with Premium'),
            ultimate: N_('FeatureLibrary|Enhanced with Ultimate')
          }
        }.freeze

        ADD_ON_LABEL_TEXT = N_('FeatureLibrary|Add-on')

        class_methods do
          extend ::Gitlab::Utils::Override

          override :available?
          def available?(user:, resource:)
            return false unless user && resource
            return false unless ::Feature.enabled?(:feature_catalog_explore_pages, resource.root_ancestor)
            return false unless user.can_admin_all_resources? || resource.member?(user)

            ::Onboarding::FeatureLibrary::CurrentPlanContext.new(resource: resource).has_upgrade_pages?
          end
        end

        private

        override :page
        def page(plan)
          copy = PAGE_COPY.fetch(plan)

          super.merge(
            title: s_(copy[:title]),
            subtitle: s_(copy[:subtitle]),
            highlights_title: s_(copy[:highlights_title]),
            credits_title: s_(CREDITS_TITLE)
          )
        end

        override :label
        def label(type, plan)
          text = type == 'add_on' ? ADD_ON_LABEL_TEXT : LABEL_TEXT.fetch(type).fetch(plan)

          super.merge(text: s_(text))
        end
      end
    end
  end
end
