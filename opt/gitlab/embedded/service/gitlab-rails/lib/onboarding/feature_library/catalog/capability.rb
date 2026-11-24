# frozen_string_literal: true

module Onboarding
  module FeatureLibrary
    module Catalog
      # A Feature catalog card that is not a nav item on its own, such as Merge controls or
      # GitLab Duo Agent Platform. Premium and Ultimate capabilities are feature highlights, some of
      # them GitLab.com limits; add-on capabilities render under "Powered by GitLab Credits".
      class Capability < Data.define(
        :id, :panel, :tier, :licensed_features, :title, :description, :icon, :docs_path,
        :shown_on_deployments, :pages, :supersedes_nav_items
      )
        # licensed_features: the licensed features behind a highlight, each first available on its tier.
        #   Empty for GitLab.com limits and add-ons. Only read by
        #   ee/spec/lib/onboarding/feature_library/catalog_drift_spec.rb.
        # pages: the tier pages that list an add-on card, per deployment. An Array applies to every
        #   deployment; a Hash sets them for some deployments and leaves the rest on every page.
        #   Highlights only appear on their own tier's page, so they keep the default.
        def initialize(
          licensed_features: [], shown_on_deployments: Catalog::DEPLOYMENTS,
          pages: Catalog::TIER_PAGES, supersedes_nav_items: [], **attributes)
          super(
            licensed_features: licensed_features.freeze,
            shown_on_deployments: shown_on_deployments.freeze,
            pages: pages_by_deployment(pages, attributes[:id]),
            supersedes_nav_items: supersedes_nav_items.freeze,
            **attributes
          )
        end

        def pages_on(deployment)
          pages.fetch(deployment)
        end

        def translated_title
          s_(title)
        end

        # A description with %{} placeholders, such as the compute minutes copy, is filled from variables.
        # A missing value raises KeyError.
        def translated_description(**variables)
          translated = s_(description)

          translated.include?('%{') ? format(translated, variables) : translated
        end

        private

        def pages_by_deployment(pages, id)
          unknown = pages.is_a?(Hash) ? pages.keys - Catalog::DEPLOYMENTS : []
          raise ArgumentError, "#{id} pages: unknown deployments #{unknown.join(', ')}" if unknown.any?

          Catalog::DEPLOYMENTS.index_with do |deployment|
            (pages.is_a?(Hash) ? pages.fetch(deployment, Catalog::TIER_PAGES) : pages).freeze
          end.freeze
        end
      end
    end
  end
end
