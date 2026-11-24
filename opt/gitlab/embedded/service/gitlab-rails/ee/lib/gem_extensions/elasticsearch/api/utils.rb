# frozen_string_literal: true

module GemExtensions
  module Elasticsearch
    module API
      module Utils # rubocop:disable Search/NamespacedClass
        # This fixes deprecation warnings from https://gitlab.com/gitlab-org/gitlab/-/issues/429071
        def __escape(string)
          return string if string == '*'

          CGI.escape(string.to_s)
        end
      end
    end
  end
end
