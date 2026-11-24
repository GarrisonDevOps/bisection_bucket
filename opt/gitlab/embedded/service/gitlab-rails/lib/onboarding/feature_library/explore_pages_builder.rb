# frozen_string_literal: true

module Onboarding
  module FeatureLibrary
    # Builds the Feature catalog Explore pages for one viewer: the pages their plan can still
    # upgrade to, each filtered to what the plan adds, with the page's upgrade CTA.
    class ExplorePagesBuilder
      include Gitlab::Routing

      PLAN_RANK = CurrentPlanContext::PLANS.each_with_index.to_h.freeze
      PLAN_NAMES = { free: N_('Free'), premium: N_('Premium'), ultimate: N_('Ultimate') }.freeze

      # Compute minutes included a month on GitLab.com, per plan. Product confirmation is tracked in
      # https://gitlab.com/gitlab-org/gitlab/-/work_items/632721.
      COMPUTE_MINUTES = { free: 400, premium: 10_000, ultimate: 50_000 }.freeze

      # The Explore pages are EE only for now. EE overrides this with the flag and membership checks.
      def self.available?(user:, resource:) # rubocop:disable Lint/UnusedMethodArgument -- EE uses them
        false
      end

      def initialize(user:, resource:, panel:)
        @user = user
        @resource = resource
        @panel = panel.to_sym
      end

      def execute
        {
          current_plan_context: plan_context.to_h,
          pages: plan_context.tier_pages.map { |plan| page(plan) }
        }
      end

      private

      attr_reader :user, :resource, :panel

      def plan_context
        @plan_context ||= CurrentPlanContext.new(resource: resource)
      end

      def base_plan
        plan_context.base_plan
      end

      def explore_pages
        @explore_pages ||= Catalog.explore_pages(panel: panel, deployment: plan_context.deployment)
      end

      def page(plan)
        explore_page = explore_pages.fetch(plan)
        values = description_values(plan)

        {
          plan: plan,
          cta: UpgradeCta.new(user: user, resource: resource, plan: plan, base_plan: base_plan).build,
          # The highlights heading names the plan, so highlight cards carry no label.
          highlights: explore_page.highlights.map { |capability| capability_item(capability, values) },
          credits: explore_page.credits.map do |capability|
            capability_item(capability, values).merge(label: label('add_on', plan))
          end,
          categories: categories(explore_page, plan)
        }
      end

      # Items the viewer's plan already includes are left out. Add-ons are never included in a plan.
      # Nav items come first in each category, then enhancements, both in catalog order.
      def categories(explore_page, plan)
        new_items = explore_page.new_items.reject { |item| included_in_base_plan?(item.tier) }
        enhancements = explore_page.enhanced_items.reject { |enhancement| included_in_base_plan?(enhancement.tier) }

        new_items_by_category = new_items.group_by(&:category)
        enhancements_by_category = enhancements.group_by { |enhancement| enhancement.nav_item.category }

        Catalog::CATEGORIES.filter_map do |id, title|
          items = new_items_by_category.fetch(id, []).map { |item| nav_item(item, plan) } +
            enhancements_by_category.fetch(id, []).map { |enhancement| enhancement_item(enhancement, plan) }
          next if items.empty?

          { id: id, title: s_(title), items: items }
        end
      end

      # Tiers are validated by the catalog spec, so an unknown tier is a content bug and should raise.
      def included_in_base_plan?(tier)
        return false if tier == :add_on

        PLAN_RANK.fetch(tier) <= PLAN_RANK.fetch(base_plan)
      end

      def nav_item(item, plan)
        {
          id: item.item_id,
          source: 'nav_item',
          title: item.translated_title,
          description: item.translated_description,
          icon: item.icon,
          docs_url: docs_url(item.docs_path),
          label: label(item.tier == :add_on ? 'add_on' : 'new', plan)
        }
      end

      def enhancement_item(enhancement, plan)
        nav_item(enhancement.nav_item, plan).merge(
          description: enhancement.text,
          label: label('enhanced', plan)
        )
      end

      def capability_item(capability, values)
        {
          id: capability.id,
          source: 'capability',
          title: capability.translated_title,
          description: capability.translated_description(**values),
          icon: capability.icon,
          docs_url: docs_url(capability.docs_path)
        }
      end

      def label(type, plan)
        { type: type, plan: plan }
      end

      # Values for the placeholders in capability descriptions. The compute minutes copy compares the
      # page's plan with the viewer's base plan.
      def description_values(plan)
        {
          plan_minutes: COMPUTE_MINUTES.fetch(plan).to_fs(:delimited),
          base_minutes: COMPUTE_MINUTES.fetch(base_plan).to_fs(:delimited),
          base_plan: s_(PLAN_NAMES.fetch(base_plan))
        }
      end

      # A docs_path may end in #section, which becomes the page anchor. The catalog spec checks
      # every docs_path points at an existing page.
      def docs_url(docs_path)
        path, anchor = docs_path.split('#', 2)

        help_page_path(path, anchor: anchor) # rubocop:disable Gitlab/DocumentationLinks/Link -- path comes from the catalog
      end
    end
  end
end

Onboarding::FeatureLibrary::ExplorePagesBuilder.prepend_mod
