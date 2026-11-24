# frozen_string_literal: true

module Ai
  module Catalog
    module Items
      class StarService
        def initialize(item, current_user, params)
          @item = item
          @current_user = current_user
          @starred = params[:starred]
        end

        def execute
          if @starred
            star
          else
            unstar
          end
        end

        private

        def star
          @item.star(@current_user)

          ServiceResponse.success(payload: { star_count: @item.reset.star_count })
        rescue ActiveRecord::RecordInvalid => e
          ServiceResponse.error(message: e.message)
        end

        def unstar
          @item.unstar(@current_user)

          ServiceResponse.success(payload: { star_count: @item.reset.star_count })
        end
      end
    end
  end
end
