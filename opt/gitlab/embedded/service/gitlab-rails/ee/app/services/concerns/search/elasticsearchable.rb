# frozen_string_literal: true

module Search
  module Elasticsearchable
    SCOPES_ADVANCED_SEARCH_ALWAYS_ENABLED = %w[users].freeze

    def use_elasticsearch?
      ::Gitlab::CurrentSettings.search_using_elasticsearch?(scope: elasticsearchable_scope)
    end

    def elasticsearchable_scope
      raise NotImplementedError
    end

    def global_elasticsearchable_scope?
      SCOPES_ADVANCED_SEARCH_ALWAYS_ENABLED.include?(params[:scope])
    end
  end
end
