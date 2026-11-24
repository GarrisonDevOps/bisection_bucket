# frozen_string_literal: true

module EE
  module EventsHelper
    extend ::Gitlab::Utils::Override

    override :event_note_target_url
    def event_note_target_url(event)
      if event.epic_note?
        group_epic_url(event.group, event.note_target, anchor: dom_id(event.target))
      elsif event.vulnerability_note?
        project_security_vulnerability_url(event.project, event.note_target, anchor: dom_id(event.target))
      else
        super
      end
    end

    override :event_wiki_page_target_url
    def event_wiki_page_target_url(event, target: event.target, **options)
      if event.group_id.present?
        group_wiki_url(event.group, target&.canonical_slug || ::Wiki::HOMEPAGE, **options)
      else
        super
      end
    end
  end
end
