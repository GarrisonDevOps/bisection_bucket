# frozen_string_literal: true

module EE
  module TermsHelper
    extend ::Gitlab::Utils::Override

    override :terms_service_notice_link
    def terms_service_notice_link(button_text)
      return super unless ::Gitlab::Saas.feature_available?(:gitlab_terms)

      terms_link = link_to('', terms_path, target: '_blank', rel: 'noopener noreferrer')

      safe_format(
        s_(
          'SignUp|By clicking %{button_text} or registering through a third party you accept the GitLab ' \
            '%{link_start}Terms of Use and acknowledge the Privacy Statement and Cookie Policy%{link_end}.'
        ),
        tag_pair(terms_link, :link_start, :link_end),
        button_text: button_text
      )
    end

    def sm_welcome_onboarding_terms_service_notice_link(button_text)
      terms_link = link_to('', 'https://about.gitlab.com/terms', target: '_blank', rel: 'noopener noreferrer')

      safe_format(
        s_(
          'SignUp|By clicking %{button_text} you accept the %{link_start}GitLab Terms ' \
            'of Use and acknowledge the Privacy Statement and Cookie Policy%{link_end}.'
        ),
        tag_pair(terms_link, :link_start, :link_end),
        button_text: button_text
      )
    end
  end
end
