# frozen_string_literal: true

module EE
  module PreferredLanguageSwitcher
    extend ::Gitlab::Utils::Override

    private

    override :language_from_params
    def language_from_params
      return super unless ::Gitlab::Saas.feature_available?(:marketing_site_language)

      # Our marketing site will be the only thing we are sure of the language placement in the url for.
      glm_source = params.permit(:glm_source)[:glm_source]
      locale = glm_source&.match(%r{\A#{::Gitlab.promo_host}/([a-z]{2})-([a-z]{2})}i)&.captures

      return [] if locale.blank?

      # This is local and then locale_region - the marketing site will always send locale-region pairs like fr-fr.
      [locale[0], "#{locale[0]}_#{locale[1]}"]
    end
  end
end
