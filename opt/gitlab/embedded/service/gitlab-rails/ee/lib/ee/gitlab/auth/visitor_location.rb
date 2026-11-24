# frozen_string_literal: true

module EE
  module Gitlab
    module Auth
      module VisitorLocation
        UNRESOLVED_COUNTRY_CODES = %w[XX T1].freeze

        def country_code
          code = request.headers[::Gitlab::Auth::VisitorLocation::HEADERS[:country]]
          return if code.blank? || UNRESOLVED_COUNTRY_CODES.include?(code)

          code
        end
      end
    end
  end
end
