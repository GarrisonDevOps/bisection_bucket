# frozen_string_literal: true

module EE
  module LabelsHelper
    extend ActiveSupport::Concern
    extend ::Gitlab::Utils::Override

    SCOPED_LABEL_BORDER_WIDTH = '2px'

    prepended do
      singleton_class.prepend self
    end

    def render_colored_label(label, in_reference: nil)
      return super unless label.scoped_label?

      render_label_text(
        label.scoped_label_key,
        css_class: "gl-label-text #{label.text_color_class}",
        bg_color: label.color
      ) + render_label_text(
        label.scoped_label_value,
        css_class: "gl-label-text-scoped",
        in_reference: in_reference
      )
    end

    def wrap_label_html(label_html, label:, for_email: false)
      return super unless label.scoped_label?

      color = label.color
      style =
        if for_email
          "color: #{color}; border-color: #{color}"
        else
          "color: #{color}; --label-inset-border: inset 0 0 0 #{SCOPED_LABEL_BORDER_WIDTH} #{color}"
        end

      content_tag(:span, label_html.html_safe, class: %w[gl-label gl-label-scoped], style: style)
    end

    # Returns a String containing HTML.
    override :label_tooltip_title_html
    def label_tooltip_title_html(label, tooltip_shows_title: false)
      tooltip_html = super
      tooltip_html = %(<span class="gl-font-bold">Scoped label</span><br>#{tooltip_html}) if label.scoped_label?

      tooltip_html
    end

    def label_dropdown_data(edit_context, opts = {})
      scoped_labels_fields = {
        scoped_labels: edit_context&.feature_available?(:scoped_labels)&.to_s
      }

      return super.merge(scoped_labels_fields) unless edit_context.is_a?(Group)

      {
        toggle: "dropdown",
        field_name: opts[:field_name] || "label_name[]",
        show_no: "true",
        show_any: "true",
        group_id: edit_context&.try(:id)
      }.merge(scoped_labels_fields, opts)
    end

    def labels_function_introduction
      return super unless @group&.feature_available?(:epics)

      _('Labels can be applied to issues, merge requests, and epics. Group labels are available for any project within the group.')
    end
  end
end
