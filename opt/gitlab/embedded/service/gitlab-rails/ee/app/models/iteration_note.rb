# frozen_string_literal: true

class IterationNote < ::SyntheticNote
  attr_accessor :iteration

  def self.from_event(event, resource: nil, resource_parent: nil)
    attrs = note_attributes('iteration', event, resource, resource_parent).merge(iteration: event.iteration)

    IterationNote.new(attrs)
  end

  def note_html
    @note_html ||= Banzai::Renderer.cacheless_render_field(self, :note, { group: group, project: project })
  end

  private

  def note_text(html: false)
    reference = iteration&.to_reference(resource_parent, format: :id)
    message = event.remove? ? "removed iteration #{reference}" : "changed iteration to #{reference}"
    message << " on this item and parent item" if event.automated
    message << " (deleted)" if event.automated && event.triggered_by_work_item.nil?
    message
  end
end
