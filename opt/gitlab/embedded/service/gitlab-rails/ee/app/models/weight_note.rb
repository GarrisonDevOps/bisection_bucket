# frozen_string_literal: true

class WeightNote < ::SyntheticNote
  attr_accessor :resource_parent, :event

  def self.from_event(event, resource: nil, resource_parent: nil)
    attrs = note_attributes('weight', event, resource, resource_parent)

    WeightNote.new(attrs)
  end

  def note_html
    @note_html ||= "<p dir=\"auto\">#{note_text(html: true)}</p>"
  end

  private

  def note_text(html: false)
    weight_text = html ? "<strong>#{event.weight}</strong>" : event.weight
    previous_weight_text = html ? "<strong>#{event.previous_weight}</strong>" : event.previous_weight

    if event.weight
      if event.previous_weight
        "changed weight to #{weight_text} from #{previous_weight_text}"
      else
        "set weight to #{weight_text}"
      end
    elsif event.previous_weight
      "removed weight of #{previous_weight_text}"
    else
      'removed weight'
    end
  end
end
