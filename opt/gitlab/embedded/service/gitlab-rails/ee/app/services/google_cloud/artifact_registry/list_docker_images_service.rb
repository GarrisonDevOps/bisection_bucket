# frozen_string_literal: true

module GoogleCloud
  module ArtifactRegistry
    class ListDockerImagesService < ::GoogleCloud::ArtifactRegistry::BaseProjectService
      VALID_ORDER_BY_COLUMNS = %w[name image_size_bytes upload_time build_time update_time media_type].freeze
      VALID_ORDER_BY_DIRECTIONS = %w[asc desc].freeze

      INVALID_PAGE_SIZE_ERROR_RESPONSE = ServiceResponse.error(message: 'Invalid page_size value').freeze
      INVALID_ORDER_BY_ERROR_RESPONSE = ServiceResponse.error(message: 'Invalid order_by value').freeze

      MAX_PAGE_SIZE = 50
      DEFAULT_PAGE_SIZE = 20

      private

      def call_client
        return INVALID_PAGE_SIZE_ERROR_RESPONSE unless valid_page_size?
        return INVALID_ORDER_BY_ERROR_RESPONSE unless valid_order_by?

        limited_page_size = [page_size, MAX_PAGE_SIZE].min

        images = client.docker_images(page_size: limited_page_size, page_token: page_token, order_by: order_by)
        ServiceResponse.success(payload: images)
      end

      def valid_page_size?
        page_size.is_a?(Integer)
      end

      def valid_order_by?
        return true if order_by.blank?

        column, direction = order_by.split(' ')

        column.in?(VALID_ORDER_BY_COLUMNS) && direction.in?(VALID_ORDER_BY_DIRECTIONS)
      end

      def page_size
        params[:page_size] || DEFAULT_PAGE_SIZE
      end

      def order_by
        params[:order_by]
      end

      def page_token
        params[:page_token]
      end
    end
  end
end
