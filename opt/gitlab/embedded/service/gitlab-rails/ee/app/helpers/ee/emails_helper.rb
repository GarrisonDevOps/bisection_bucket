# frozen_string_literal: true

module EE
  module EmailsHelper
    extend ::Gitlab::Utils::Override

    override :action_title
    def action_title(url)
      return "View Epic" if url.split("/").include?('epics')

      super
    end

    override :note_email_body
    def note_email_body(note, format: :html)
      ::Gitlab::WorkItems::DuoQuestionEmailBody.rewrite(note, format: format)
    end

    override :service_desk_email_additional_text
    def service_desk_email_additional_text
      return unless show_email_additional_text?

      ::Gitlab::CurrentSettings.email_additional_text
    end

    def show_email_additional_text?
      License.feature_available?(:email_additional_text) && ::Gitlab::CurrentSettings.email_additional_text.present?
    end
  end
end
