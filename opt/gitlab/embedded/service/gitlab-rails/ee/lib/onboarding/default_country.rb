# frozen_string_literal: true

module Onboarding
  class DefaultCountry
    include ::Gitlab::Utils::StrongMemoize

    NOT_OFFERED = 'not_offered'
    ACCEPTED = 'accepted'
    CHANGED = 'changed'

    def initialize(request)
      @request = request
    end

    def code
      detected = ::Gitlab::Auth::VisitorLocation.new(request).country_code
      detected if ::World.countries_for_select.any? { |_name, alpha2| alpha2 == detected }
    end
    strong_memoize_attr :code

    def outcome_for(selected)
      return NOT_OFFERED unless code

      selected == code ? ACCEPTED : CHANGED
    end

    private

    attr_reader :request
  end
end
