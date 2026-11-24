# frozen_string_literal: true

module AppSec
  module Dast
    module Profiles
      class BaseService < BaseProjectService
        private

        def valid_tags?
          return true unless tag_list?

          tag_list.size == params[:tag_list].size
        end

        def tag_list?
          params.key?(:tag_list)
        end

        def tag_list
          return [] if params[:tag_list].empty?

          @tag_list ||= ::Ci::Tag.named_any(params[:tag_list])
        end

        def tags
          if tag_list?
            tag_list
          else
            []
          end
        end

        def error(message, opts = {})
          ServiceResponse.error(message: message, **opts)
        end
      end
    end
  end
end
