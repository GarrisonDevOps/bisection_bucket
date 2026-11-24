# frozen_string_literal: true

module EE
  module Search
    module ScopeHandlers
      module Groups
        include ActionView::Helpers::NumberHelper
        include ::Gitlab::Utils::StrongMemoize

        extend ActiveSupport::Concern
        extend ::Gitlab::Utils::Override

        PRELOADS = [:route].freeze

        class_methods do
          extend ::Gitlab::Utils::Override

          override :available?
          def available?
            return super unless ::Gitlab::CurrentSettings.elasticsearch_search?

            ::Elastic::DataMigrationService.migration_has_finished?(:backfill_groups_to_elasticsearch)
          end

          def advanced_search_available?
            ::Gitlab::CurrentSettings.elasticsearch_search? && available?
          end
        end

        override :highlight_map
        def highlight_map
          return super unless advanced_search_enabled?

          response_mapper.highlight_map
        end

        private

        override :fetch_results
        def fetch_results(page:, per_page:, preload_method: nil)
          return super unless advanced_search_enabled?

          response_mapper(page: page, per_page: per_page, preload_method: preload_method).records
        end

        override :total_count
        def total_count
          return super unless advanced_search_enabled?

          response_mapper.total_count
        end

        override :count_limit
        def count_limit
          return super unless advanced_search_enabled?

          ::Gitlab::Elastic::SearchResults::ELASTIC_COUNT_LIMIT
        end

        override :count_limit_message
        def count_limit_message
          return super unless advanced_search_enabled?

          "#{format_count(count_limit)}+"
        end

        override :format_count
        def format_count(value)
          return super unless advanced_search_enabled?

          number_with_delimiter(value)
        end

        def advanced_search_enabled?
          self.class.advanced_search_available?
        end
        strong_memoize_attr :advanced_search_enabled?

        def response_mapper(
          page: ::Search::ScopeHandlers::Base::DEFAULT_PAGE,
          per_page: ::Search::ScopeHandlers::Base::DEFAULT_PER_PAGE,
          preload_method: nil
        )
          @response_mapper ||= begin
            options = elasticsearch_options(page: page, per_page: per_page, preload_method: preload_method)
            search_query = ::Search::Elastic::GroupQueryBuilder.new(query: query, options: options).build

            ::Gitlab::Search::Client.execute_search(query: search_query, options: options) do |response|
              ::Search::Elastic::ResponseMapper.new(response, options)
            end
          end
        end

        def elasticsearch_options(page:, per_page:, preload_method: nil)
          {
            current_user: current_user,
            index_name: ::Search::Elastic::References::Group.index,
            klass: ::Group,
            preloads: PRELOADS,
            preload_method: preload_method,
            order_by: search_results.order_by,
            sort: search_results.sort,
            page: page,
            per_page: per_page
          }.merge(search_level_options)
        end

        def search_level_options
          group = search_results.try(:group)
          return {} unless group

          {
            search_level: :group,
            group_ids: [group.id],
            excluded_ids: [group.id],
            root_ancestor_ids: [group.root_ancestor.id]
          }
        end
      end
    end
  end
end
