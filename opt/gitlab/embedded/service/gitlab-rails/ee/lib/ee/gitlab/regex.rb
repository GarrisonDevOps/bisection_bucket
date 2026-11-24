# frozen_string_literal: true

module EE
  module Gitlab
    module Regex
      extend ActiveSupport::Concern

      class_methods do
        def epic(reference_postfix = nil)
          /(?<epic>\d{1,20})#{Regexp.escape(reference_postfix) if reference_postfix}(?<format>\+s{,1})?/
        end
      end
    end
  end
end
