# frozen_string_literal: true

module Gitlab
  module Pagination
    class OffsetPagination < Base
      COUNT_CACHE_EXPIRES_IN = 15.minutes

      attr_reader :request_context

      delegate :params, :header, :request, to: :request_context

      def initialize(request_context)
        @request_context = request_context
      end

      def paginate(relation, exclude_total_headers: false, skip_default_order: false, without_count: false, skip_pagination_check: false, count_cache_key: nil, counter: nil)
        ordered_relation = add_default_order(relation, skip_default_order: skip_default_order)

        paginate_with_limit_optimization(ordered_relation, without_count: without_count, skip_pagination_check: skip_pagination_check, count_cache_key: count_cache_key, counter: counter).tap do |data|
          add_pagination_headers(data, exclude_total_headers, without_count)
        end
      end

      private

      def paginate_with_limit_optimization(relation, without_count:, skip_pagination_check: false, count_cache_key: nil, counter: nil)
        pagination_data = if !skip_pagination_check && needs_pagination?(relation)
                            relation.page(page).per(per_page)
                          else
                            relation
                          end

        return pagination_data unless pagination_data.is_a?(ActiveRecord::Relation)

        pagination_data.preset_total_count(counter.call(pagination_data)) if counter && !without_count
        apply_cached_count(pagination_data, count_cache_key) if count_cache_key && !without_count

        if without_count || exceeeds_count?(pagination_data)
          # The call to `total_count_with_limit` memoizes `@arel` because of a call to `references_eager_loaded_tables?`
          # We need to call `reset` because `without_count` relies on `@arel` being unmemoized
          pagination_data.reset.without_count
        else
          pagination_data
        end
      end

      # Page 1 always recounts but only refreshes a count already cached: most callers never request page 2, and
      # caching every page 1 fills the global write limit. The cached last page recounts so a walk never stops early
      def apply_cached_count(paginated_data, count_cache_key)
        count_sql = paginated_data.except(:offset, :limit, :order).to_sql
        cache_key = [:offset_pagination_total_count, count_cache_key, OpenSSL::Digest::SHA256.hexdigest(count_sql)]
        cached_count = Rails.cache.read(cache_key)
        return if paginated_data.current_page == 1 && cached_count.nil?

        if reuse_cached_count?(paginated_data, cached_count)
          paginated_data.preset_total_count(cached_count)
        elsif !count_cache_writes_throttled?
          Rails.cache.write(cache_key, paginated_data.total_count_with_limit, expires_in: COUNT_CACHE_EXPIRES_IN)
        end
      end

      def count_cache_writes_throttled?
        Gitlab::ApplicationRateLimiter.throttled?(:offset_pagination_count_cache_write, scope: { scope: :global })
      end

      def reuse_cached_count?(paginated_data, cached_count)
        return false unless cached_count && paginated_data.current_page > 1
        # Over the limit no total is shown and the next page comes from the loaded records, so any page can reuse it
        return true if cached_count > Kaminari::ActiveRecordRelationMethods::MAX_COUNT_LIMIT

        paginated_data.current_page < (cached_count.to_f / paginated_data.limit_value).ceil
      end

      def needs_pagination?(relation)
        return true unless relation.respond_to?(:current_page)
        return true if page.present? && relation.current_page != page.to_i
        return true if per_page.present? && relation.limit_value != per_page.to_i

        false
      end

      def add_default_order(relation, skip_default_order: false)
        return relation if skip_default_order

        if relation.is_a?(ActiveRecord::Relation) && relation.order_values.empty?
          relation = relation.order(:id) # rubocop: disable CodeReuse/ActiveRecord
        end

        relation
      end

      def add_pagination_headers(paginated_data, exclude_total_headers, without_count)
        Gitlab::Pagination::OffsetHeaderBuilder.new(
          request_context: self, per_page: paginated_data.limit_value, page: paginated_data.current_page,
          next_page: paginated_data.next_page, prev_page: paginated_data.prev_page,
          total: total_count(paginated_data), total_pages: total_pages(paginated_data)
        ).execute(exclude_total_headers: exclude_total_headers, data_without_counts: without_count || data_without_counts?(paginated_data))
      end

      def data_without_counts?(paginated_data)
        paginated_data.is_a?(Kaminari::PaginatableWithoutCount) || paginatable_array_exceeds_count?(paginated_data)
      end

      def paginatable_array_exceeds_count?(paginated_data)
        paginated_data.is_a?(Kaminari::PaginatableArray) &&
          paginated_data.total_count >= Kaminari::ActiveRecordRelationMethods::MAX_COUNT_LIMIT
      end

      def total_count(paginated_data)
        paginated_data.total_count unless data_without_counts?(paginated_data)
      end

      def total_pages(paginated_data)
        return if data_without_counts?(paginated_data)

        # Ensure there is in total at least 1 page
        [paginated_data.total_pages, 1].max
      end

      def exceeeds_count?(paginated_data)
        limited_total_count = paginated_data.total_count_with_limit

        limited_total_count > Kaminari::ActiveRecordRelationMethods::MAX_COUNT_LIMIT
      end

      def page
        to_integer(params[:page])
      end

      def per_page
        to_integer(params[:per_page])
      end

      def to_integer(value)
        case value
        when Integer
          value
        when String
          Integer(value, 10, exception: false)
        end
      end
    end
  end
end
